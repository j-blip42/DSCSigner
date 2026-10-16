# DSC Signer - batch PDF signing with an Indian DSC token.
# Copyright (C) 2026 Deccan Stat Books
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
# for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Built with Claude (Anthropic) directing the keyboard, not the decisions.
"""Local web interface for sign_dsc.py.

Serves sign_dsc_ui.html on 127.0.0.1 and drives the same signing code the
command line uses - sign_dsc.sign_documents() - so there is one implementation
of the actual signing, not two.

    python sign_dsc_ui.py

It binds the loopback interface only, picks a free port, mints a random key
that every API call must present, and opens your browser at the right URL.
Nothing is served to the network and nothing is sent off the machine.

WHY A LOCAL SERVER AND NOT A WEB PAGE
    The page has to reach the PKCS#11 driver, the USB token, the documents on
    this disk and the copy of Word that converts them. A page hosted anywhere
    else can do none of that, and a browser will not hand a web page a file's
    path on disk either - hence the native file dialog behind the "Choose
    files" button.

THE PIN
    Typed into the page, posted once over the loopback interface, held in a
    local variable for the one signing session and dropped. It is never
    written to disk, never logged, and never put in a URL. The request log is
    suppressed for the same reason.
"""
import http.server
import io
import json
import os
import secrets
import socket
import sys
import threading
import webbrowser

import fitz

import sign_dsc as S

HERE = S.asset_root()          # sys._MEIPASS when frozen, this folder when not
PAGE = os.path.join(HERE, "sign_dsc_ui.html")
KEY = secrets.token_urlsafe(24)
PREVIEWS = {}          # name -> PNG bytes, kept in memory only
OPENABLE = set()       # paths this session wrote, the only ones /api/open takes

# What the preview is rendered at. The page works in points and multiplies by
# this, so the box it draws sits exactly where the signature will go - change
# it here and nothing else needs to know.
PREVIEW_DPI = 100


def cert_facts(cert):
    validity = cert["tbs_certificate"]["validity"]
    nb = validity["not_before"].native
    na = validity["not_after"].native
    return {
        "cn": S.subject_cn(cert),
        "org": S.subject_org(cert),
        "issuer": (cert.issuer.native.get("organization_name")
                   or cert.issuer.native.get("common_name") or "?"),
        "from": nb.strftime("%d-%m-%Y"),
        "to": na.strftime("%d-%m-%Y"),
        "expired": na < S.datetime.now(S.timezone.utc),
    }


def resolve_token(want_label=None, want_cert=None, pin=None):
    """(dll, slot_index, slot_id, token, picked, chain, entries) or raise."""
    chosen = S.choose_token(S.scan_tokens(verbose=False), want_label)
    if not chosen:
        raise RuntimeError("No token found, or more than one is present. "
                           "Plug in a single token and try again.")
    dll, slot_index, slot_id, tok = chosen
    try:
        entries = S.read_certs(tok, pin)
    except Exception as exc:
        if pin is None:
            return dll, slot_index, slot_id, tok, None, [], []
        raise RuntimeError(f"Could not read the token's certificates: "
                           f"{type(exc).__name__}: {exc}")
    if not entries:
        return dll, slot_index, slot_id, tok, None, [], []
    leaves, cas, others = S.split_certs(entries)
    if want_cert:
        w = want_cert.lower()
        leaves = [e for e in leaves
                  if w in (S.subject_cn(e[2]) or "").lower()
                  or w in (e[1] or "").lower()]
    if not leaves:
        raise RuntimeError("This token carries no certificate that can sign.")
    if len(leaves) > 1:
        names = ", ".join(S.subject_cn(e[2]) or "?" for e in leaves)
        raise RuntimeError(f"More than one signing certificate on this token "
                           f"({names}). The web interface cannot choose "
                           f"between them; use the command line with --cert.")
    return (dll, slot_index, slot_id, tok, leaves[0],
            [c for _i, _l, c in cas], entries)


def selection(body):
    paths = [p for p in body.get("paths", []) if os.path.isfile(p)]
    if not paths:
        raise RuntimeError("No readable documents in the selection.")
    return paths


def hand_placements(body):
    """[(origin, page number, box)] from boxes dragged about on the preview.

    The page speaks in points from the TOP left, because that is how the
    rendered image reads; the signer wants points from the bottom left. The
    flip happens here, at the edge, so nothing further in has to know that
    the interface has its own idea of which way up a page is.

    Anything malformed is dropped rather than guessed at: a placement that
    does not survive this is one nobody looked at on screen.
    """
    out = []
    for item in (body.get("placements") or [])[:2000]:
        try:
            origin = item["origin"]
            pageno = int(item["page"])
            x, y, w, h = (float(v) for v in item["rect"])
            ph = float(item["ph"])
        except (KeyError, TypeError, ValueError):
            continue
        if not origin or pageno < 1 or w <= 0 or h <= 0 or ph <= 0:
            continue
        out.append((origin, pageno, (x, ph - y - h, x + w, ph - y)))
    return out


def typed_remarks(body):
    """[(origin, page, x, y, text, size, colour)] from the text boxes.

    Positions arrive in points from the top left, the way the preview reads,
    and S.write_remarks() takes them that way. Empty boxes are dropped. Text
    the PDF font cannot show is refused outright rather than dropped: a line
    that silently goes missing from a signed page is the worst outcome here.
    """
    out = []
    for item in (body.get("texts") or [])[:200]:
        try:
            origin = item["origin"]
            pageno = int(item["page"])
            x, y = float(item["x"]), float(item["y"])
            size = float(item.get("size") or 9)
            colour = S.REMARK_COLOURS.get(item.get("colour") or "black")
        except (KeyError, TypeError, ValueError):
            continue
        if not origin or pageno < 1 or colour is None:
            continue
        try:
            text = S.remark_text(item.get("text"))
        except ValueError as exc:
            raise RuntimeError(f"Text on {os.path.basename(origin)} page "
                               f"{pageno}: {exc}. Nothing has been signed.")
        if not text.strip():
            continue
        lo, hi = S.REMARK_SIZES
        out.append((origin, pageno, x, y, text, min(max(size, lo), hi),
                    colour))
    return out


def typed_stamps(body):
    """[(origin, page, x, y, w, h, kind)] for the images placed on the preview.

    Top-left points, as the preview reads; S.with_remarks() keeps each one on
    its page and its size within reason, and refuses a kind with no image.
    """
    out = []
    for item in (body.get("stamps") or [])[:200]:
        try:
            origin = item["origin"]
            pageno = int(item["page"])
            x, y, w, h = (float(item[k]) for k in ("x", "y", "w", "h"))
            kind = str(item.get("kind") or "round")
        except (KeyError, TypeError, ValueError):
            continue
        if kind not in S.STAMP_KINDS:
            continue
        if origin and pageno >= 1 and w > 0 and h > 0:
            out.append((origin, pageno, x, y, w, h, kind))
    return out


def stamp_info(kind):
    """What the page needs to draw one saved image: its URL and its shape."""
    path = S.stamp_file(kind)
    if not os.path.isfile(path):
        return {"stamp": None, "where": path}
    try:
        pix = fitz.Pixmap(path)
        w, h = pix.width, pix.height
        pix = None
    except Exception:
        return {"stamp": None, "where": path,
                "error": "The saved image could not be read."}
    # The modification time busts the browser's cache when it is replaced.
    return {"stamp": f"/stamp.png?kind={kind}&k={KEY}"
                     f"&v={int(os.path.getmtime(path))}",
            "aspect": h / w if w else 1.0, "where": path}


def save_stamp(src, kind="round"):
    """Copy a chosen image into stamp_file(kind) as a PNG, keeping transparency.

    Any image fitz can read is accepted - a PNG with a clear background is
    best; a JPEG scan of a stamp works, but its white paper comes with it.
    """
    dst = S.stamp_file(kind)
    try:
        pix = fitz.Pixmap(src)
    except Exception as exc:
        raise RuntimeError(f"That file is not an image the signer can read "
                           f"({type(exc).__name__}).")
    if pix.width < 50 or pix.height < 50:
        raise RuntimeError("That image is too small to be a stamp.")
    if pix.n - pix.alpha not in (1, 3):   # CMYK and the like: make it RGB
        pix = fitz.Pixmap(fitz.csRGB, pix)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".new"
    pix.save(tmp, output="png")    # the ".new" suffix names no format
    os.replace(tmp, dst)


def placement(body):
    """(pages, side) as the page asked for them, or a plain-English refusal.

    Both are checked here rather than trusted: the page is the only caller
    today, but this is an HTTP endpoint and a bad page spec must come back as
    a sentence, not a traceback.
    """
    pages = (body.get("pages") or "1").strip() or "1"
    if len(pages) > 200:
        raise RuntimeError("That page list is too long to be meant.")
    try:
        side = S.normalise_side(body.get("side") or S.DEFAULT_SIDE)
    except ValueError as exc:
        raise RuntimeError(str(exc))
    try:
        S.parse_pages(pages, 1)         # syntax only; the count is per document
    except ValueError as exc:
        raise RuntimeError(f"Pages: {exc}. Use 1, 1,3, 2-5, all, first "
                           f"or last.")
    return pages, side


def placement_note(notes, origin):
    """Why nothing could be placed on `origin`, in S.plan()'s own words.

    plan() reports a document it could not place as "cannot place on NAME:
    reason" rather than raising, so the rest of the batch still goes through.
    That sentence is the one worth showing beside the document in the results
    table; the fallback is only there so a missing row is never the outcome.
    """
    head = f"cannot place on {os.path.basename(origin)}: "
    for note in notes:
        if note.strip().startswith(head):
            return note.strip()[len(head):]
    return "no signature could be placed on this document"


def build_rows(prep, pages, side, notes=None):
    """Plan the stamps: the chosen pages, at the chosen side of the foot.

    The interface does not offer the anchor search - a corner stamp is
    predictable, which is what you want when signing a stack of documents you
    have not read. What it does offer is where along the foot it goes and
    which pages get one, and those are honoured exactly: nothing is nudged
    aside to avoid existing content, so the overlap check and the confirmation
    in front of it are what stand between a chosen position and a covered
    paragraph.

    `prep` is a S.Prepared - Word documents in the selection have already
    become temporary PDFs, which live only as long as the S.converted() block
    the caller is inside.
    """
    if not prep.pairs:
        raise RuntimeError("Nothing in the selection could be prepared for "
                           "signing.")
    notes = [] if notes is None else notes
    rows = S.plan(prep.pairs, S.DEFAULT_ANCHOR, pages, True, side=side,
                  exact=True, log=notes.append)
    if not rows:
        raise RuntimeError("Nothing could be placed. "
                           + " ".join(n.strip() for n in notes))
    return rows


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "sign_dsc_ui"

    def log_message(self, *a):
        pass                    # never log request lines; PINs travel in POSTs

    # ------------------------------------------------------------ plumbing
    def _send(self, code, payload, ctype="application/json"):
        data = (json.dumps(payload).encode("utf-8")
                if ctype == "application/json" else payload)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    def _authorised(self, key):
        # A random key on top of loopback-only binding. Without it any page
        # you happen to have open could POST to this port in the background.
        if not secrets.compare_digest(key or "", KEY):
            self._send(403, {"error": "bad or missing key"})
            return False
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            self._send(403, {"error": "unexpected Host header"})
            return False
        return True

    # ----------------------------------------------------------------- GET
    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            key = ""
            if "?" in self.path:
                from urllib.parse import parse_qs
                key = (parse_qs(self.path.split("?", 1)[1]).get("k") or [""])[0]
            if not secrets.compare_digest(key, KEY):
                self._send(403, b"Open the URL printed in the terminal.",
                           "text/plain; charset=utf-8")
                return
            with open(PAGE, "rb") as fh:
                self._send(200, fh.read(), "text/html; charset=utf-8")
            return
        if path == "/stamp.png":
            # Personal, so behind the key like the page itself: any other
            # page open in the browser could otherwise load it from this port.
            from urllib.parse import parse_qs
            query = parse_qs(self.path.split("?", 1)[-1])
            key = (query.get("k") or [""])[0]
            if not secrets.compare_digest(key, KEY):
                self._send(403, b"forbidden", "text/plain")
                return
            try:
                kind = (query.get("kind") or ["round"])[0]
                with open(S.stamp_file(kind), "rb") as fh:
                    self._send(200, fh.read(), "image/png")
            except (OSError, ValueError):
                self._send(404, b"no stamp", "text/plain")
            return
        if path.startswith("/png/"):
            png = PREVIEWS.get(path[5:])
            if png is None:
                self._send(404, b"gone", "text/plain")
            else:
                self._send(200, png, "image/png")
            return
        self._send(404, {"error": "not found"})

    # ---------------------------------------------------------------- POST
    def do_POST(self):
        if not self._authorised(self.headers.get("X-Key")):
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self._send(400, {"error": "bad request body"})
            return
        route = getattr(self, "api_" + self.path.strip("/").split("/")[-1], None)
        if route is None:
            self._send(404, {"error": "no such endpoint"})
            return
        try:
            self._send(200, route(body))
        except RuntimeError as exc:
            # RuntimeError is what this module raises when it has a sentence
            # for the user - a page list that does not parse, a token that is
            # not there. Prefixing those with the class name makes a plain
            # instruction read like a crash.
            self._send(200, {"error": str(exc)})
        except Exception as exc:
            self._send(200, {"error": f"{type(exc).__name__}: {exc}"})
        finally:
            body = None         # drop any PIN as soon as the call is done

    # ------------------------------------------------------------ handlers
    def api_probe(self, body):
        dll, slot_index, slot_id, tok, picked, chain, entries = resolve_token(
            body.get("token"), body.get("cert"))
        serial = tok.serial
        if isinstance(serial, bytes):
            serial = serial.decode("ascii", "replace")
        leaves, cas, others = S.split_certs(entries) if entries else ([], [], [])
        out = {
            "module": dll, "token": tok.label, "slot_id": slot_id,
            "slot_index": slot_index, "serial": serial,
            "n_certs": len(entries), "n_leaves": len(leaves),
            "n_ca": len(cas), "n_other": len(others),
            "deferred": picked is None,
        }
        if picked:
            cert = picked[2]
            out["cert"] = cert_facts(cert)
            # tok.label so the previewed stamp reads exactly as the signed one
            # will - the first line names this token.
            out["stamp"] = S.stamp_text_for(
                cert, body.get("designation") or None, tok.label).replace(
                    "%(ts)s", "<date>")
            # No list of expected names to compare against - the stamp carries
            # nothing but the certificate, so the certificate is simply shown.
            cn = (S.subject_cn(cert) or "").strip().upper()
            out["warning"] = f"Everything signed now will be stamped {cn!r}."
        return out

    def api_browse(self, body):
        # The dialog has to run on the main thread on Windows, so it is
        # marshalled there rather than opened from this request thread.
        return {"paths": ask_paths(body.get("mode") == "folder")}

    def api_stamp(self, body):
        """Every saved image, by kind; with choose=KIND, pick a new one first."""
        kind = body.get("choose")
        cancelled = False
        if kind:
            if kind not in S.STAMP_KINDS:
                raise RuntimeError(f"No such stamp: {kind}.")
            got = _ask("image")
            if got:
                save_stamp(got[0], kind)
            else:
                cancelled = True
        return {"kinds": {k: stamp_info(k) for k in S.STAMP_KINDS},
                "cancelled": cancelled}

    def api_preview(self, body):
        paths = selection(body)
        pages, side = placement(body)
        out, bad, notes = [], 0, []
        # Word documents are converted for the length of this block only; the
        # previews are PNGs held in memory, so nothing needs the temp PDFs
        # once it ends.
        with S.converted(paths) as prep:
            rows = build_rows(prep, pages, side, notes)
            for row in rows:
                doc = S.open_planned(row)
                page = doc[row.pno]
                hits = S.blocking(page, row.box)
                if hits:
                    bad += 1
                # The page is rendered clean and the box is drawn over it by
                # the browser, because a box painted into the image cannot be
                # picked up and moved. The two have to agree exactly, hence
                # the geometry below: the page in points, and the scale the
                # image was rendered at.
                W, H = page.rect.width, page.rect.height
                obs = S.obstacle_rects(page)
                buf = page.get_pixmap(dpi=PREVIEW_DPI).tobytes("png")
                npages = doc.page_count - (1 if row.prepend else 0)
                doc.close()
                # The URL carries an id, not the document's name. A name with
                # a space in it - which is most of them - is percent-encoded
                # by the browser before it asks for the image, and the lookup
                # here is against the raw path, so the thumbnail came back 404
                # and the preview silently showed a broken image.
                key = str(len(PREVIEWS))
                PREVIEWS[key] = buf
                out.append({"name": row.name, "origin": row.origin,
                            "page": row.pno + 1, "hits": hits[:3],
                            "note": row.note, "added_page": row.prepend,
                            "png": f"/png/{key}", "npages": npages,
                            # everything below is in points, top-left origin,
                            # which is how the image reads
                            "pw": round(W, 1), "ph": round(H, 1),
                            "scale": PREVIEW_DPI / 72.0,
                            "rect": [round(row.box[0], 1),
                                     round(H - row.box[3], 1),
                                     round(row.box[2] - row.box[0], 1),
                                     round(row.box[3] - row.box[1], 1)],
                            "obs": obs})
            errors = [f"{os.path.basename(p)}: {why}" for p, why in prep.failed]
            # A document that could not be placed at all - page 7 of a
            # four-page file - is named here rather than being silently
            # absent from the thumbnails.
            errors += [n.strip() for n in notes]
        return {"rows": out, "collisions": bad, "errors": errors,
                "pages": pages, "side": side}

    def api_page(self, body):
        """One page of one document, rendered for typing text onto.

        For a page that carries no signature - a remark on page 2 of a
        document signed on page 3 - so it is not among the preview's rows.
        """
        origin = body.get("origin") or ""
        if not os.path.isfile(origin):
            raise RuntimeError("That document is no longer there.")
        try:
            pageno = int(body.get("page"))
        except (TypeError, ValueError):
            raise RuntimeError("Give a page number.")
        with S.converted([origin]) as prep:
            if not prep.pairs:
                raise RuntimeError(prep.failed[0][1] if prep.failed
                                   else "That document could not be opened.")
            doc = fitz.open(prep.pairs[0][0])
            try:
                if not 1 <= pageno <= doc.page_count:
                    raise RuntimeError(f"{os.path.basename(origin)} has "
                                       f"{doc.page_count} page"
                                       f"{'s' if doc.page_count != 1 else ''}"
                                       f", not {pageno}.")
                page = doc[pageno - 1]
                W, H = page.rect.width, page.rect.height
                buf = page.get_pixmap(dpi=PREVIEW_DPI).tobytes("png")
                npages = doc.page_count
            finally:
                doc.close()
        key = str(len(PREVIEWS))
        PREVIEWS[key] = buf
        return {"name": os.path.basename(origin), "origin": origin,
                "page": pageno, "png": f"/png/{key}", "npages": npages,
                "pw": round(W, 1), "ph": round(H, 1)}

    def api_sign(self, body):
        paths = selection(body)
        pages, side = placement(body)
        # The stamp is drawn on top of the page, and the position was asked
        # for rather than found, so it can cover text. The page puts that in
        # front of the user; this is the server refusing to sign until it has
        # been answered, so no other caller can skip the question either.
        if body.get("confirm_overwrite") is not True:
            raise RuntimeError("The placement warning was not confirmed. "
                               "Nothing has been signed.")
        remarks = typed_remarks(body)
        stamps = typed_stamps(body)
        log = []
        # The typed text, stamps and letterhead are written into a temp copy
        # before anything is planned or signed, so the signature covers them.
        # A document they cannot be written on moves to prep.failed and is
        # not signed.
        with S.converted(paths, log=log.append) as converted_prep, \
                S.with_remarks(converted_prep, remarks, stamps,
                               log=log.append) as prep:
            notes = []
            if not prep.pairs:
                raise RuntimeError("Nothing could be signed. " + " ".join(
                    f"{os.path.basename(o)}: {why}." for o, why in prep.failed))
            hand = hand_placements(body)
            if hand:
                # Positions dragged about on the preview. They are used as
                # they are - re-running the placement rule here would quietly
                # undo what the user just did with the mouse.
                rows = S.rows_from_placements(prep.pairs, hand,
                                              log=notes.append)
                if not rows:
                    raise RuntimeError(
                        "None of the positions could be used. "
                        + " ".join(n.strip() for n in notes))
            else:
                rows = build_rows(prep, pages, side, notes)
            log += [n.strip() for n in notes]
            docs = S.group_rows(rows)
            # A document nothing could be placed on - page 7 of a four-page
            # file - never reaches the signer and would otherwise be missing
            # from the results table entirely, which reads as a clean run.
            placed = {origin for origin, _group in docs}
            unplaced = [(o, placement_note(notes, o))
                        for _pdf, o in prep.pairs if o not in placed]
            # Asked for on the desktop, never in the page. See ask_pin().
            pin = ask_pin(len(docs), len(rows))
            if not pin:
                return {"error": "Cancelled at the PIN prompt. Nothing signed."}
            dll, slot_index, slot_id, tok, picked, chain, _entries = (
                resolve_token(body.get("token"), body.get("cert"), pin=None))
            if picked is None:  # token hides its certificates until login
                dll, slot_index, slot_id, tok, picked, chain, _e = resolve_token(
                    body.get("token"), body.get("cert"), pin=pin)
            results, err = S.sign_documents(
                rows, dll, slot_index, tok, picked, chain, pin,
                body.get("reason") or S.REASON, body.get("place") or S.PLACE,
                body.get("suffix") or S.SUFFIX, None,
                body.get("designation") or None, log=log.append,
                mark_style=body.get("mark_style") or S.MARK_STYLE)
            pin = None
            failed = list(prep.failed) + unplaced
        if err:
            hint = ("A wrong PIN is the usual cause. Repeated wrong PINs can "
                    "lock the token, so check before retrying."
                    if S.pin_related(err) else
                    "This failed before the PIN was submitted, so no attempt "
                    "was used against the token.")
            return {"error": f"Could not open a signing session: "
                             f"{type(err).__name__}: {err}. {hint}"}
        checked = S.verify_outputs(results)
        dsts = {os.path.basename(dst): dst for _s, dst, _ok, _e in results}
        rows_out = [{"name": n, "size": sz, "sigs": ns, "ok": ok, "error": e,
                     "path": dsts.get(n, "")}
                    for n, sz, ns, ok, e in checked]
        # A document that could not be converted never reached the signer, so
        # it has no result of its own. It still belongs in the table - dropping
        # it would report a clean run over a selection that was not.
        rows_out += [{"name": os.path.basename(p), "size": None, "sigs": None,
                      "ok": False, "error": why, "path": ""}
                     for p, why in failed]
        good = sum(1 for r in rows_out if r["ok"])
        folder = ""
        for r in rows_out:
            if r["ok"] and r["path"]:
                r["path"] = os.path.normpath(r["path"])
                OPENABLE.add(r["path"])
                if not folder:
                    folder = os.path.dirname(r["path"])
                    OPENABLE.add(folder)
        return {"rows": rows_out, "ok": good, "bad": len(rows_out) - good,
                "folder": folder, "log": log}

    def api_open(self, body):
        """Open a signed file, or its folder, in Explorer.

        A browser cannot open a local path, so it is done here. Only paths
        this session actually produced are accepted - the page must never be
        able to talk the server into opening something arbitrary.
        """
        path = os.path.normpath(body.get("path") or "")
        if path not in OPENABLE:
            raise RuntimeError("That path was not produced by this session.")
        if not os.path.exists(path):
            raise RuntimeError("That file is no longer there.")
        os.startfile(path)      # noqa: S606 - local, user-initiated
        return {"ok": True}

    def api_quit(self, body):
        threading.Timer(0.4, lambda: os._exit(0)).start()
        return {"ok": True}


# ------------------------------------------------------------ native dialogs
_dialog_request = []
_dialog_done = threading.Event()
_dialog_result = []
_dialog_error = []
_dialog_busy = threading.Lock()

DIALOG_TIMEOUT = 90
PIN_TIMEOUT = 300


def _ask(kind, timeout=DIALOG_TIMEOUT):
    """Ask the main thread to raise a dialog, and wait for the answer.

    One at a time: a second request while a dialog is already open would sit
    behind it and time out, which looks exactly like a dead button.
    """
    if not _dialog_busy.acquire(blocking=False):
        raise RuntimeError("A dialog is already open - it may be behind "
                           "this window.")
    try:
        _dialog_result.clear()
        _dialog_error.clear()
        _dialog_done.clear()
        _dialog_request.append(kind)
        if not _dialog_done.wait(timeout=timeout):
            _dialog_request.clear()
            raise RuntimeError(
                f"The dialog did not come back within {timeout}s. If it "
                f"opened behind another window, close it and try again.")
        if _dialog_error:
            # Never let a broken dialog read as "the user cancelled" - that
            # sends you hunting for a window that was never drawn.
            raise RuntimeError(f"The dialog failed to open: "
                               f"{_dialog_error[0]}")
        return list(_dialog_result)
    finally:
        _dialog_busy.release()


def ask_paths(folder):
    return _ask("folder" if folder else "files")


def ask_pin(count, signatures=None):
    """The token PIN, taken in a native dialog rather than in the page.

    The PIN must never be typed into the browser. A page with an
    <input type="password"> is exactly what a browser's password manager
    latches onto - Chrome and Edge deliberately ignore autocomplete="off" on
    password fields - so the PIN could be offered up for saving and syncing to
    a cloud account. Asking here keeps it out of the DOM, off the HTTP hop,
    and out of the browser entirely.
    """
    got = _ask(("pin", count, signatures), timeout=PIN_TIMEOUT)
    return got[0] if got else None


def pump_dialogs():
    """Run tkinter on the main thread; it refuses to work anywhere else."""
    import tkinter
    from tkinter import filedialog
    root = tkinter.Tk()
    root.withdraw()

    def to_front():
        # Without an owner window the dialog opens behind the browser, and the
        # server then blocks on a dialog nobody can see. Raising a topmost,
        # focused parent first is what drags it in front.
        try:
            root.attributes("-topmost", True)
            root.deiconify()
            root.lift()
            root.focus_force()
            root.withdraw()
            root.update()
        except Exception:
            pass

    def ask_pin_window(count, signatures=None):
        """A masked PIN prompt owned by this process, not by the browser.

        Deliberately NOT transient(root): the root here is withdrawn, and
        Windows hides a transient window whose master is hidden - the dialog
        gets created and then never appears, leaving the browser waiting on a
        prompt nobody can see. The native file dialogs dodge this because Tk
        hands those to the OS. This one is a real Tk window, so it raises
        itself instead of leaning on a parent.
        """
        win = tkinter.Toplevel(root)
        win.title("Token PIN")
        win.resizable(False, False)
        what = (f"{count} document{'s' if count != 1 else ''}")
        if signatures and signatures != count:
            what += (f" carrying {signatures} signature"
                     f"{'s' if signatures != 1 else ''} in all")
        tkinter.Label(
            win, justify="left",
            text=(f"Enter the token PIN to sign {what}.\n"
                  "It is used once and not stored.")
        ).pack(padx=20, pady=(18, 10))
        var = tkinter.StringVar()
        entry = tkinter.Entry(win, show="*", textvariable=var, width=30)
        entry.pack(padx=20, pady=(0, 14))
        held = {}

        def accept(*_a):
            held["pin"] = var.get()
            win.destroy()

        def cancel(*_a):
            held["pin"] = None
            win.destroy()

        bar = tkinter.Frame(win)
        bar.pack(padx=20, pady=(0, 18), fill="x")
        tkinter.Button(bar, text="Cancel", command=cancel).pack(side="right")
        tkinter.Button(bar, text="Sign", command=accept).pack(side="right",
                                                              padx=(0, 8))
        entry.bind("<Return>", accept)
        win.bind("<Escape>", cancel)
        win.protocol("WM_DELETE_WINDOW", cancel)

        # Put it on screen and in front, in the middle, under its own steam.
        win.update_idletasks()
        w, h = win.winfo_width(), win.winfo_height()
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"+{(sw - w) // 2}+{(sh - h) // 3}")
        win.deiconify()
        win.attributes("-topmost", True)
        win.lift()
        win.focus_force()
        entry.focus_force()
        win.grab_set()
        win.update()
        root.wait_window(win)
        var.set("")                 # do not leave it sitting in a Tk variable
        return [held.get("pin")] if held.get("pin") else []

    def serve_one(kind):
        if isinstance(kind, tuple) and kind[0] == "pin":
            return ask_pin_window(*kind[1:])
        to_front()
        if kind == "image":
            chosen = filedialog.askopenfilename(
                title="Stamp or letterhead image", parent=root,
                filetypes=[("Images", "*.png *.jpg *.jpeg"),
                           ("PNG with a clear background", "*.png")])
            return [os.path.normpath(chosen)] if chosen else []
        if kind == "folder":
            d = filedialog.askdirectory(title="Folder of documents",
                                        parent=root)
            if not d:
                return []
            return S.folder_inputs(d)
        anything = " ".join("*" + e for e in S.INPUT_EXTS)
        word = " ".join("*" + e for e in S.WORD_EXTS)
        chosen = filedialog.askopenfilenames(
            title="Documents to sign", parent=root,
            filetypes=[("PDF and Word documents", anything),
                       ("PDF files", "*.pdf"),
                       ("Word documents", word)])
        # Tk hands this back as a tuple normally, but as one packed string on
        # some builds; splitlist normalises both.
        if isinstance(chosen, str):
            chosen = root.tk.splitlist(chosen)
        return [os.path.normpath(p) for p in chosen]

    def tick():
        try:
            while _dialog_request:
                kind = _dialog_request.pop(0)
                got = []
                try:
                    got = serve_one(kind)
                except Exception as exc:
                    _dialog_error.append(f"{type(exc).__name__}: {exc}")
                try:
                    _dialog_result.extend(got)
                finally:
                    _dialog_done.set()
        finally:
            # Rescheduling from a finally is the point: if anything above
            # throws, the pump must still be alive for the next click. It was
            # losing the loop that made the button look dead.
            root.after(120, tick)

    root.after(120, tick)
    root.mainloop()


def open_browser(url):
    """Get a browser onto the page, by whatever route works.

    webbrowser.open() is not dependable here - it can return quietly having
    done nothing, and the working directory being a network drive does not
    help. os.startfile hands the URL to the shell, which is what actually
    launches the default browser on Windows.
    """
    if os.name == "nt":
        try:
            os.startfile(url)
            return True
        except Exception:
            pass
    try:
        return bool(webbrowser.open(url))
    except Exception:
        return False


def main():
    if not os.path.isfile(PAGE):
        print(f"Missing {PAGE}")
        return 1
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    port = srv.server_address[1]
    url = f"http://127.0.0.1:{port}/?k={KEY}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    # flush explicitly: stdout is block-buffered when it is a pipe, and
    # anything reading this output would otherwise wait for the buffer.
    print("=" * 72, flush=True)
    print("DSC Signer - running on the loopback interface only.", flush=True)
    print("=" * 72 + "\n", flush=True)
    print("Open this address. The key is required - 127.0.0.1 on its own,", flush=True)
    print("which is what a browser's autocomplete will offer you, returns 403.\n",
          flush=True)
    print(f"  {url}\n", flush=True)
    print("Leave this window open. Ctrl+C, or Quit in the page, stops it.",
          flush=True)
    if "--no-browser" not in sys.argv:
        if not open_browser(url):
            print("\nCould not open a browser automatically. Copy the "
                  "address above into one.", flush=True)
    try:
        pump_dialogs()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
