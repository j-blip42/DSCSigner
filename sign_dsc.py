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
"""Offline PDF signer for the office DSC token.

Signs PDFs on this machine with the USB token. Nothing goes to the internet:
no timestamp authority, no CRL or OCSP fetch, no validation info embedded. The
private key never leaves the token, and the PIN is typed at the prompt, held in
memory only, never logged, written, or passed on the command line.

Originals are never touched - each output is written alongside as
"<name> - signed.pdf".

WORD DOCUMENTS
    A .docx, .doc, .docm or .rtf can be handed over directly. Word itself
    converts it - the same export as File > Save as PDF, so the same
    pagination and the same fonts - and the resulting PDF is signed. That PDF
    is temporary and is deleted afterwards: the only new file beside
    Report.docx is "Report - signed.pdf". Microsoft Word must be installed;
    without it those files are reported as failures and the PDFs in the same
    run are still signed.

PLACEMENT
    By default the visible signature is anchored to the signatory's printed
    name in the signature block, so it lands where a wet signature would.
      - if the anchor is found in the right-hand column of a two-column
        signature block, the stamp goes immediately above the printed name
        (beside where the other party signs);
      - if the anchor is in the left column, the stamp goes to its right;
      - if the anchor is not found at all, it falls back to the bottom-right
        of the chosen page, right edge flush with the page's own text margin
        rather than a fixed inset from the paper. --corner asks for that
        placement outright, skips the search, and defaults to page one.
    A corner stamp is placed in the footer white space below the body text,
    not over it. Where the text runs so far down that even the foot of the
    page would clash, it still goes there and the collision check says so.
    Always run --preview first on a document you have not signed before, and
    look at the PNGs. --preview also refuses any box that would sit on top of
    existing text.

    --corner-side left|centre|right asks for one of the three positions along
    the foot of the page and puts the stamp EXACTLY there: no search for clear
    space, no shifting it out of the way, no added signature page. That is the
    point of asking - a chosen position that moves is not a chosen position -
    so the stamp can land on existing text, and it is your business to preview
    it. Every overlap is named in --preview and again before the PIN prompt,
    where it has to be confirmed separately.

    --page takes a list: "1,3" or "2-5" or "all" or "last". Each page named
    gets its own visible stamp and its own signature, all in the one output
    file, applied one after another in a single token session.

USAGE
    python sign_dsc.py --probe
        Find the token, name the PKCS#11 module, and report which certificate
        on it would sign. No PIN needed on most tokens. Run this first after
        changing tokens: it fails where --sign would, without touching a PDF.

    python sign_dsc.py <file.pdf | file.docx | folder> [...] --preview
        Render a PNG per document with the signature box drawn in red, and
        report any collision with existing text.

    python sign_dsc.py <file.pdf | file.docx | folder> [...] --sign
        Confirm, prompt for the PIN once, sign everything in one session,
        then reopen each output and verify the signature is embedded.

OPTIONS
    --corner          skip the anchor search and put the stamp in the
                      bottom-right corner, its right edge flush with the
                      page's own text margin and clear of the last line.
    --corner-side X   left, centre or right along the foot of the page, placed
                      exactly there. Implies --corner. Nothing is moved to
                      avoid existing content, so preview it.
    --anchor "TEXT"   text to anchor the stamp to. Defaults to the name on
                      the inserted certificate; falls back to --corner
                      placement if the token cannot be read.
    --page N          1-based pages: "3", "1,3", "2-5", "all", "first",
                      "last", or any mixture - "1,4-6,last". Every page named
                      is stamped and signed.
                      Default: with --corner, page one - a corner stamp is the
                      document's signature and belongs at the front. Otherwise
                      the page the anchor is found on, else the last.
    --reason "TEXT"   signature reason. Omitted unless you give one - the
                      signature cannot vouch for a reason.
    --place "TEXT"    signature location. Defaults to the place named on the
                      certificate, and is omitted if it names none.
    --suffix "TEXT"   output suffix                (default: " - signed")
    --tsa URL         add a trusted timestamp. THIS MAKES ONE NETWORK CALL PER
                      SIGNATURE. Omit it to stay fully offline.

    Only needed when the token itself is ambiguous:
    --module PATH     use this PKCS#11 driver instead of searching System32
    --token LABEL     pick among several tokens plugged in at once
    --cert "NAME"     pick among several signing certificates on one token
    --designation "TEXT"
                      second line of the stamp. Defaults to the qualification
                      recorded for our own certificate, and to nothing at all
                      for anyone else's. Pass "" to force it off.
    --mark-style X    the DSB mark behind the stamp (default: cover)
                        cover  badge across the whole stamp, stretched to it
                        band   badge cropped to the stamp's shape, not stretched
                        seal   badge at full height on the right, text clear
                        none   plain stamp

WHICH TOKENS THIS HAS ACTUALLY BEEN USED WITH
    Two vendors, against real tokens and real documents:
      - ePass2003 / HYP2003, two DSCs, through
        C:\\Windows\\System32\\eps2003csp11v2.dll
      - mToken CryptoID (Longmai), through
        C:\\Windows\\System32\\CryptoIDA_pkcs11.dll
    Everything else in KNOWN_MODULES is listed on reasonable grounds but has
    not been proven against a real token here.

    That does not mean other tokens will not work. The module list is only a
    head start: any PKCS#11 driver sitting in System32 is picked up
    automatically, and --module points at one anywhere else. A token from an
    unfamiliar provider stands a fair chance of simply working.

    If it does not, the code is yours - it is published under the AGPL. Add
    your driver to KNOWN_MODULES, or run --probe to see what your machine
    exposes and what is on the token. If that is not your line of work, hand
    this file to any capable AI assistant and ask it to add support for your
    vendor; it is a short list to extend.

CHANGING TOKENS
    Tokens differ by provider in ways that matter here: a different driver
    DLL, and a different set of objects loaded onto the token. Some providers
    store only the signing certificate; others store the CA chain beside it.
    The signing certificate is therefore chosen explicitly - the leaf that is
    not a CA and carries a signing key usage - rather than assuming the token
    holds exactly one certificate.

    The visible stamp names whoever the certificate names. Signing with a
    different DSC than usual is announced before the PIN prompt, not silently.

NOTES
    A signature made without --tsa carries this machine's clock rather than a
    trusted time. That is normal for offline signing and is accepted for
    departmental filings, but it is worth knowing.

    If a document is already signed, signing again adds a second signature
    incrementally rather than replacing the first.
"""
import contextlib
import getpass
import glob
import os
import shutil
import sys
import tempfile
import traceback
from datetime import datetime, timezone

import fitz

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")

# PKCS#11 modules commonly present on Windows for Indian DSC tokens, tried in
# this order. The list is a head start, not the whole story: any other PKCS#11
# module sitting in System32 is picked up by the glob in candidate_modules(),
# so a token from a provider nobody here has seen before is still found.
KNOWN_MODULES = [
    ("SignatureP11.dll",       "ProxKey / Watchdata"),
    ("CryptoIDA_pkcs11.dll",   "mToken CryptoID (Longmai)"),
    ("eps2003csp11v2.dll",     "ePass2003"),
    ("eps2003csp11.dll",       "ePass2003, older driver"),
    ("HyperPKICsp11_2003.dll", "HyperPKI / Hypersecu"),
    ("InnaITPKCS11Driver.dll", "InnaIT"),
    ("eTPKCS11.dll",           "SafeNet / Gemalto eToken"),
    ("wdpkcs.dll",             "Watchdata"),
    ("ShuttleCsp11_3003.dll",  "Watchdata Shuttle"),
]

# Nothing about a particular signatory is baked in. The anchor defaults to the
# name on the certificate, the location to the place named on it, and the
# reason is simply left out rather than asserting something the signature
# cannot support. --anchor, --place and --reason override all three.
DEFAULT_ANCHOR = None
REASON = None
PLACE = None
SUFFIX = " - signed"

# The visible stamp, in points. 150x48 is about 53 x 17mm - a little smaller
# than a rubber stamp, and half the area of the 215x64 this used to be, which
# took up more of a page's foot than a signature has any business taking. The
# floor is set by the date line: see STAMP_COLS below.
BOX_W, BOX_H = 150.0, 48.0

# Smaller than this and the stamp is not a signature any more, whatever a
# request asks for - the date line alone is 104pt at the smallest font used.
MIN_BOX_W, MIN_BOX_H = 60.0, 24.0

# Where a corner stamp may sit along the foot of the page. Vertical position is
# not offered: a signature belongs at the foot, and a stamp halfway up a page
# is on the body text by definition.
CORNER_SIDES = ("left", "centre", "right")
DEFAULT_SIDE = "right"

# The three numbers below move together, and the date line is what sets the
# floor. Courier makes a character 0.6 * font wide, and "Date: 2026-09-18
# 21:19:49 IST" is 29 characters - 122pt at 7pt - which is never wrapped,
# because a date broken over two lines looks like a mistake. So the box has to
# be at least that wide plus the border and padding, and STAMP_COLS has to be
# at least as wide as the date or a long name will wrap further than the date
# runs and the stamp stops looking square.
#
# STAMP_FONT must stay an int: pyHanko does rational arithmetic on the font
# size when it lays the box out, and a float raises "both arguments should be
# Rational instances" at signing time, not at import.
STAMP_FONT = 7
STAMP_COLS = 30

# The mark behind the stamp, derived from the DSB icon. Kept small on purpose:
# the image is embedded into every signature, so the full-size icon would add
# well over a megabyte to each signed page. A missing file means no mark, never
# a failed signature.
#
#   cover  the badge across the whole stamp. The badge is square and the stamp
#          is about 3.4:1, so it is stretched; at this opacity that reads as a
#          watermark rather than a distortion.
#   band   the badge scaled up and cropped to the stamp's shape, so it covers
#          without stretching, showing a band through the middle of the shield.
#   seal   the badge at full height, right-aligned, text running clear of it.
#   none   plain stamp.
def asset_root():
    """Where the bundled assets live.

    PyInstaller unpacks data files into a temporary directory and points
    sys._MEIPASS at it, so a frozen build must look there rather than beside
    the executable.
    """
    return getattr(sys, "_MEIPASS",
                   os.path.dirname(os.path.abspath(__file__)))


HERE = asset_root()
MARK_FILES = {
    "cover": os.path.join(HERE, "sign_dsc_mark_full.png"),
    "band": os.path.join(HERE, "sign_dsc_mark_band.png"),
    "seal": os.path.join(HERE, "sign_dsc_mark.png"),
}
MARK_OPACITY = {"cover": 0.20, "band": 0.20, "seal": 0.18}
MARK_STYLE = "cover"
MARK_PAD = 6
SEAL_PAD = 11               # see stamp_style(): sets the seal badge's width

# The signatory's name, in orange, with the rest of the stamp in black. RGB,
# 0 to 1, as PDF wants it. Set it to None for a stamp that is entirely black.
NAME_COLOUR = (1.0, 0.42, 0.0)


# ----------------------------------------------------------------- arguments
def arg(flag, default=None):
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default


def is_input(name):
    """A file this can be pointed at: a PDF, or a Word document."""
    return os.path.basename(name).lower().endswith(INPUT_EXTS)


def folder_inputs(folder):
    """Signable documents in a folder.

    Two things are left out. Word's lock files (~$name.docx) are not
    documents, and a folder with something open in Word is full of them.
    Anything already carrying the output suffix is skipped so that running
    over a folder twice signs the documents again rather than the signed
    copies of them.
    """
    out = []
    for f in sorted(os.listdir(folder)):
        if f.startswith("~$") or SUFFIX in f or not is_input(f):
            continue
        out.append(os.path.normpath(os.path.join(folder, f)))
    return out


def collect_inputs(argv):
    """Every positional argument that is a signable file, or a folder of them."""
    flags = {"--probe", "--preview", "--sign", "--anchor", "--page", "--reason",
             "--place", "--suffix", "--tsa", "--module", "--token", "--cert",
             "--designation", "--corner", "--corner-side", "--mark-style"}
    takes_value = {"--anchor", "--page", "--reason", "--place", "--suffix",
                   "--tsa", "--module", "--token", "--cert", "--designation",
                   "--corner-side", "--mark-style"}
    out, skip = [], False
    for i, a in enumerate(argv[1:]):
        if skip:
            skip = False
            continue
        if a in flags:
            skip = a in takes_value
            continue
        if os.path.isdir(a):
            out += folder_inputs(a)
        elif os.path.isfile(a) and is_input(a):
            # A file named outright is taken as named - including one that
            # already ends in the suffix, which is how you add a second
            # signature to something already signed.
            out.append(a)
        else:
            print(f"  ignoring (not a PDF, Word document or folder): {a}")
    return out


# ------------------------------------------------------------ Word documents
# A Word document is converted by Word itself, so what gets signed is exactly
# the PDF you would have got from File > Save as PDF - the same fidelity, the
# same fonts, the same pagination. No second rendering engine is introduced,
# and nothing here has to understand the .docx format.
#
# The converted PDF is temporary and is deleted when the operation ends. The
# only new file beside "Report.docx" is "Report - signed.pdf".
WORD_EXTS = (".docx", ".doc", ".docm", ".rtf")
INPUT_EXTS = (".pdf",) + WORD_EXTS

WD_EXPORT_PDF = 17              # wdExportFormatPDF
WD_OPTIMIZE_FOR_PRINT = 0       # wdExportOptimizeForPrint
WD_NO_BOOKMARKS = 0             # wdExportCreateNoBookmarks
WD_DO_NOT_SAVE = 0              # wdDoNotSaveChanges
WD_ALERTS_NONE = 0              # wdAlertsNone
MSO_MACROS_DISABLED = 3         # msoAutomationSecurityForceDisable

# Word will stop and ask for a password on an encrypted document. That prompt
# belongs to Word, appears wherever Word feels like putting it, and would hang
# the run behind a dialog nobody is looking for. Handing it a password that
# cannot be right makes it raise instead, which is reportable.
BAD_PASSWORD = "\x00sign_dsc_no_password\x00"


def is_word(path):
    return os.path.basename(path).lower().endswith(WORD_EXTS)


class Prepared:
    """A selection turned into PDFs: what can be signed, and what could not.

    pairs is [(pdf, origin)] - the PDF to plan and sign against, and the file
    the user actually chose. They are the same thing for a PDF input.
    failed is [(origin, message)] for documents that could not be converted;
    those are reported rather than quietly dropped.
    """

    def __init__(self):
        self.pairs = []
        self.failed = []


def word_start():
    """A private, invisible Word instance. Raises with a plain-English error."""
    try:
        import pythoncom
        from win32com.client import DispatchEx
    except ImportError:
        raise RuntimeError(
            "signing a Word document needs pywin32 (pip install pywin32); "
            "convert it to PDF yourself and sign that instead")
    pythoncom.CoInitialize()
    try:
        # DispatchEx, not Dispatch: a separate instance of Word owned by this
        # process. Dispatch would attach to the copy the user already has
        # open, and quitting it at the end would take their unsaved work with
        # it.
        app = DispatchEx("Word.Application")
        app.Visible = False
        app.DisplayAlerts = WD_ALERTS_NONE
        # Never run macros out of a document being signed. This is a batch
        # nobody is watching, and .docm is in the list.
        try:
            app.AutomationSecurity = MSO_MACROS_DISABLED
        except Exception:
            pass                # older builds; not worth failing the run over
    except Exception as exc:
        pythoncom.CoUninitialize()
        raise RuntimeError(
            f"Microsoft Word could not be started, so a Word document cannot "
            f"be converted here ({type(exc).__name__}); convert it to PDF "
            f"yourself and sign that instead")
    return app


def word_quit(app):
    try:
        app.Quit(SaveChanges=WD_DO_NOT_SAVE)
    except Exception:
        pass
    try:
        import pythoncom
        pythoncom.CoUninitialize()
    except Exception:
        pass


def word_error(exc):
    """Word's own sentence out of a COM error.

    pywin32 raises com_error carrying (hresult, 'Exception occurred.',
    excepinfo, arg). The part worth putting in front of anyone is the
    description buried in excepinfo - "Word experienced an error trying to
    open the file" - not the tuple around it.
    """
    info = getattr(exc, "excepinfo", None)
    try:
        if info and len(info) > 2 and info[2]:
            return " ".join(str(info[2]).split())
    except Exception:
        pass
    return f"{type(exc).__name__}: {exc}"


def word_export(app, src, dst):
    """Export one Word document to dst as PDF. The original is opened read-only."""
    src, dst = os.path.abspath(src), os.path.abspath(dst)
    doc = app.Documents.Open(FileName=src,
                             ReadOnly=True,
                             AddToRecentFiles=False,
                             ConfirmConversions=False,
                             Visible=False,
                             PasswordDocument=BAD_PASSWORD,
                             WritePasswordDocument=BAD_PASSWORD)
    try:
        doc.ExportAsFixedFormat(OutputFileName=dst,
                                ExportFormat=WD_EXPORT_PDF,
                                OpenAfterExport=False,
                                OptimizeFor=WD_OPTIMIZE_FOR_PRINT,
                                BitmapMissingFonts=True,
                                DocStructureTags=True,
                                CreateBookmarks=WD_NO_BOOKMARKS)
    finally:
        doc.Close(SaveChanges=WD_DO_NOT_SAVE)
    # Word reporting no error is not the same as Word having written a file.
    if not os.path.isfile(dst) or os.path.getsize(dst) == 0:
        raise RuntimeError("Word reported no error but wrote no PDF")


@contextlib.contextmanager
def converted(paths, log=None):
    """Yield a Prepared for `paths`, converting any Word documents to PDF.

    The converted PDFs live in the temp folder and are deleted when the block
    ends, whatever happens inside it - so the only new file beside a .docx is
    its signed PDF, and a readable copy of the document does not outlive the
    operation that needed it.

    Nothing is cached between operations: previewing and then signing converts
    twice. That costs a few seconds and buys the guarantee that what is signed
    is the document as it stands at the moment you sign it, not as it stood
    when you previewed it.
    """
    say = log or (lambda *a: None)
    prep = Prepared()
    temps = []
    app = None
    cannot = None
    if any(is_word(p) for p in paths):
        try:
            app = word_start()
        except Exception as exc:
            cannot = str(exc)
    try:
        for p in paths:
            if not is_word(p):
                prep.pairs.append((p, p))
                continue
            if app is None:
                prep.failed.append((p, cannot))
                continue
            fd, tmp = tempfile.mkstemp(suffix=".pdf", prefix="sign_dsc_word_")
            os.close(fd)
            temps.append(tmp)
            try:
                word_export(app, p, tmp)
                prep.pairs.append((tmp, p))
                say(f"  converted {os.path.basename(p)} to PDF with Word")
            except Exception as exc:
                why = word_error(exc)
                prep.failed.append((p, why))
                say(f"  FAILED to convert {os.path.basename(p)}: {why}")
        yield prep
    finally:
        if app is not None:
            word_quit(app)
        for t in temps:
            try:
                os.remove(t)
            except OSError:
                pass


# ------------------------------------------------------------- typed remarks
# A few lines typed onto the page before it is signed - a remark against a
# column, a reference number beside the signature. They are written into the page content
# itself, not added as annotations, so the signature covers them and nobody can
# edit them afterwards without breaking it.
#
# Helvetica, because every PDF reader has it and nothing needs embedding. The
# interface draws the same text in Arial, which has Helvetica's metrics, at the
# same line height - which is what makes the box you drag land where the text
# is written. REMARK_ASCENT is where the baseline falls inside the first line
# at that line height; change one and the other has to follow.
REMARK_FONT = "helv"
REMARK_LEADING = 1.2
REMARK_ASCENT = 0.947
REMARK_SIZES = (6, 24)
REMARK_MAX_CHARS = 600
REMARK_COLOURS = {
    "black": (0.0, 0.0, 0.0),
    "blue": (0.05, 0.2, 0.65),
    "red": (0.75, 0.1, 0.1),
}

# What a paste out of Word or a browser tends to carry, put back into
# characters the built-in font has.
_REMARK_PLAIN = str.maketrans({
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "–": "-", "—": "-", "−": "-", " ": " ",
    "…": "...", "₹": "Rs.", "\t": "    ",
})


def remark_text(text):
    """The text as it will be written, or ValueError with a sentence.

    The built-in font covers Latin-1 and nothing else. A character outside it
    would come out as a question mark on a signed document, so it is refused
    here rather than discovered there.
    """
    text = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    text = text.translate(_REMARK_PLAIN).rstrip()
    if len(text) > REMARK_MAX_CHARS:
        raise ValueError(f"a text item is longer than {REMARK_MAX_CHARS} "
                         f"characters")
    bad = sorted({c for c in text if c != "\n" and
                  (ord(c) > 255 or ord(c) < 32)})
    if bad:
        raise ValueError(f"the text uses characters the PDF font cannot "
                         f"show: {' '.join(bad[:8])}")
    return text


def write_remarks(page, remarks):
    """Write [(x, y, text, size, colour)] onto `page`.

    x, y is the top left of the text in points from the top left of the page
    as it is displayed - the way the preview reads - so a rotated page is
    turned back into its own coordinates here, and the text rotated with it.
    """
    to_page = page.derotation_matrix
    for x, y, text, size, colour in remarks:
        for i, line in enumerate(text.split("\n")):
            if not line.strip():
                continue
            at = fitz.Point(x, y + size * (REMARK_ASCENT + REMARK_LEADING * i))
            page.insert_text(at * to_page, line, fontsize=size,
                             fontname=REMARK_FONT, color=colour,
                             rotate=page.rotation)


# The office's own images - the round rubber stamp, the address stamp, the
# letterhead. They are kept per user rather than beside the program: they are
# personal, they must survive the program being rebuilt or updated, and the
# program's folder is the published source. The interface copies a chosen
# image here; nothing else writes to them.
STAMP_DIR = os.path.join(
    os.environ.get("APPDATA") or os.path.expanduser("~"), "DSC Signer")
STAMP_KINDS = {
    "round": "stamp.png",
    "address": "address.png",
    "letterhead": "letterhead.png",
}
# Points across. A round stamp is ~100; a letterhead runs the page's width,
# which is what the top end is for - the page itself is the real limit.
STAMP_SIZES = (30.0, 1200.0)


def stamp_file(kind):
    """Where the image for `kind` is kept. ValueError for an unknown kind."""
    if kind not in STAMP_KINDS:
        raise ValueError(f"no such stamp: {kind!r}")
    return os.path.join(STAMP_DIR, STAMP_KINDS[kind])


def write_stamps(page, stamps, xrefs=None):
    """Put images at [(x, y, w, h, path)], top-left points as displayed.

    Pass the same `xrefs` dict for every page of one document and each image
    is embedded once and referenced from every place it is used. Its
    transparency is kept, so the page shows round it.
    """
    to_page = page.derotation_matrix
    xrefs = {} if xrefs is None else xrefs
    for x, y, w, h, path in stamps:
        box = fitz.Rect(x, y, x + w, y + h) * to_page
        if path in xrefs:
            page.insert_image(box, xref=xrefs[path], rotate=page.rotation)
        else:
            xrefs[path] = page.insert_image(box, filename=path,
                                            rotate=page.rotation)


@contextlib.contextmanager
def with_remarks(prep, remarks, stamps=(), log=None):
    """Yield a Prepared whose PDFs carry the typed text and the stamps.

    `remarks` is [(origin, page number 1-based, x, y, text, size, colour)];
    `stamps` is [(origin, page number 1-based, x, y, w, h, kind)], each drawn
    from stamp_file(kind). Each document with any is copied to the temp folder and
    written there; the copies are deleted when the block ends. A document
    whose additions cannot be written is moved to failed rather than signed
    without them - a signature over a page missing the text you typed is
    worse than no signature.

    The copy is saved incrementally where it can be, so a document that
    already carries a signature keeps it intact.
    """
    say = log or (lambda *a: None)
    by_origin = {}
    for origin, pageno, x, y, text, size, colour in remarks:
        by_origin.setdefault(origin, []).append((pageno, x, y, text, size,
                                                 colour))
    stamped = {}
    for origin, pageno, x, y, w, h, kind in stamps:
        path = stamp_file(kind)
        if not os.path.isfile(path):
            raise RuntimeError(f"A {kind} stamp was placed, but no image has "
                               f"been chosen for it. Nothing has been signed.")
        stamped.setdefault(origin, []).append((pageno, x, y, w, h, path))
        by_origin.setdefault(origin, [])
    out = Prepared()
    out.failed = list(prep.failed)
    temps = []
    try:
        for src, origin in prep.pairs:
            if origin not in by_origin:
                out.pairs.append((src, origin))
                continue
            items = by_origin.pop(origin)
            seals = stamped.get(origin, [])
            name = os.path.basename(origin)
            fd, tmp = tempfile.mkstemp(suffix=".pdf", prefix="sign_dsc_text_")
            os.close(fd)
            temps.append(tmp)
            try:
                shutil.copyfile(src, tmp)
                doc = fitz.open(tmp)
                try:
                    pages = {}
                    for pageno, x, y, text, size, colour in items:
                        if not 1 <= pageno <= doc.page_count:
                            raise ValueError(
                                f"text on page {pageno}, but the document "
                                f"has {doc.page_count}")
                        page = doc[pageno - 1]
                        W, H = page.rect.width, page.rect.height
                        pages.setdefault(pageno, []).append((
                            min(max(x, 0.0), W - 1), min(max(y, 0.0), H - 1),
                            text, size, colour))
                    seal_pages = {}
                    for pageno, x, y, w, h, path in seals:
                        if not 1 <= pageno <= doc.page_count:
                            raise ValueError(
                                f"stamp on page {pageno}, but the document "
                                f"has {doc.page_count}")
                        page = doc[pageno - 1]
                        W, H = page.rect.width, page.rect.height
                        # Resized as a whole, never squashed: a round stamp
                        # stays round.
                        lo, hi = STAMP_SIZES
                        if w <= 0 or h <= 0:
                            raise ValueError("a stamp with no size")
                        k = min(max(w, lo), hi, W) / w
                        k = min(k, H / h)
                        w, h = w * k, h * k
                        seal_pages.setdefault(pageno, []).append((
                            min(max(x, 0.0), W - w), min(max(y, 0.0), H - h),
                            w, h, path))
                    # Stamp first, text after: typed text written over the
                    # stamp stays readable, as it would on paper.
                    xrefs = {}
                    for pageno, items_on in seal_pages.items():
                        write_stamps(doc[pageno - 1], items_on, xrefs)
                    for pageno, items_on in pages.items():
                        write_remarks(doc[pageno - 1], items_on)
                    if doc.can_save_incrementally():
                        # Compressed explicitly: left alone, the stamp goes
                        # in as raw pixels - 86 KB of PNG became 5.7 MB.
                        doc.save(tmp, incremental=True,
                                 encryption=fitz.PDF_ENCRYPT_KEEP,
                                 deflate=True, deflate_images=True)
                        written = tmp
                    else:
                        # A file that needed repairing on open cannot take an
                        # incremental update; it is rewritten whole instead.
                        fd, written = tempfile.mkstemp(
                            suffix=".pdf", prefix="sign_dsc_text_")
                        os.close(fd)
                        temps.append(written)
                        doc.save(written, garbage=0, deflate=True,
                                 deflate_images=True)
                finally:
                    doc.close()
                out.pairs.append((written, origin))
                n = sum(len(v) for v in pages.values())
                if n:
                    say(f"  {name}: {n} text item{'s' if n != 1 else ''} "
                        f"written on page{'s' if len(pages) > 1 else ''} "
                        + ", ".join(str(p) for p in sorted(pages)))
                if seal_pages:
                    say(f"  {name}: stamp placed on page"
                        f"{'s' if len(seal_pages) > 1 else ''} "
                        + ", ".join(str(p) for p in sorted(seal_pages)))
            except Exception as exc:
                why = f"could not write the typed text or stamp: {exc}"
                out.failed.append((origin, why))
                say(f"  FAILED {name}: {why}")
        for origin in by_origin:
            say(f"  ignoring text for a document that is not in this "
                f"selection: {os.path.basename(str(origin))}")
        yield out
    finally:
        for t in temps:
            try:
                os.remove(t)
            except OSError:
                pass


# ----------------------------------------------------------------- placement
def fit_to_page(box, page):
    """Keep a placement inside the paper, whatever the geometry asked for.

    The stamp is a fixed BOX_W x BOX_H, which is wider than some pages are - a
    cropped statement, a compliment slip. Better a squeezed stamp on the page
    than a correctly proportioned one hanging off it.
    """
    W, H = page.rect.width, page.rect.height
    edge_x, edge_y = min(18.0, W / 4), min(18.0, H / 4)
    x0, y0, x1, y1 = box
    x0, y0 = max(x0, edge_x), max(y0, edge_y)
    x1, y1 = min(x1, W - edge_x), min(y1, H - edge_y)
    return (x0, y0, max(x1, x0 + 1), max(y1, y0 + 1))


def normalise_side(side):
    """"left" / "centre" / "right" from what a person or a page might send."""
    got = (side or "right").strip().lower()
    got = {"center": "centre", "middle": "centre", "mid": "centre",
           "": "right"}.get(got, got)
    if got not in CORNER_SIDES:
        raise ValueError(f"placement must be one of "
                         f"{', '.join(CORNER_SIDES)}, not {side!r}")
    return got


def parse_pages(spec, page_count):
    """(page indices, pages asked for that do not exist), 0-based, in order.

    Takes "3", "1,3", "2-5", "all", "first", "last", "auto", and mixtures of
    those - "1,4-6,last". Duplicates collapse, so "1,first" is one page and
    one signature, not two on top of each other.

    Pages past the end of a document are reported rather than dropped
    quietly: asking for page 5 of a three-page file is a mistake worth seeing,
    and it is a per-document answer in a batch where the files differ in
    length.
    """
    text = (spec if isinstance(spec, str) else
            ",".join(str(s) for s in (spec or []))).strip().lower()
    if text in ("", "auto", "first"):
        return [0], []
    if text == "all":
        return list(range(page_count)), []

    wanted, missing = [], []

    def take(n):                        # n is 1-based as the user counts
        if 1 <= n <= page_count:
            if n - 1 not in wanted:
                wanted.append(n - 1)
        elif n not in missing:
            missing.append(n)

    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        if part == "first":
            take(1)
        elif part == "last":
            take(page_count)
        elif "-" in part[1:]:           # a dash after the first character is
                                        # a range; a leading one is a negative
            lo, hi = part.split("-", 1)
            try:
                lo, hi = int(lo), int(hi)
            except ValueError:
                raise ValueError(f"{part!r} is not a page range")
            if lo < 1 or hi < lo:
                raise ValueError(f"{part!r} is not a page range")
            if hi - lo > 999:
                raise ValueError(f"{part!r} covers too many pages")
            for n in range(lo, hi + 1):
                take(n)
        else:
            try:
                n = int(part)
            except ValueError:
                raise ValueError(f"{part!r} is not a page number")
            if n < 1:
                raise ValueError("pages are counted from 1")
            take(n)
    if not wanted and not missing:
        raise ValueError(f"no pages in {spec!r}")
    return sorted(wanted), missing


def onto_page(box, page):
    """Slide a box onto the paper, keeping its size. None if it cannot fit.

    This is the containment fit_to_page() does not do, and deliberately so:
    that one squeezes a stamp that is wider than the paper, and guarantees
    only that the result is not inside out. A box positioned by hand needs
    the other guarantee - that the whole of it is on the page - because a
    signature half over the edge is invisible in a reader and a stamp
    flattened to a point tall is worse than no stamp.
    """
    W, H = page.rect.width, page.rect.height
    x0, y0, x1, y1 = box
    w, h = min(x1 - x0, W), min(y1 - y0, H)
    if w < MIN_BOX_W or h < MIN_BOX_H:
        return None
    x0 = min(max(x0, 0.0), W - w)
    y0 = min(max(y0, 0.0), H - h)
    return (x0, y0, x0 + w, y0 + h)


def corner_box(page, side="right", flush=True):
    """Along the foot of the page, on the margins the page itself uses.

    A fixed inset from the paper edge lines up with the document only by
    accident - every template has its own margins. Measuring the text block
    instead drops the stamp into the clear band below the last line where
    there is one.

    side is "left", "centre" or "right". Centre is measured on the paper, not
    on the text block: a stamp at the foot of the page reads as centred
    against the page it sits on, and a text block that is off-centre - a bound
    report with a wide inner margin - would otherwise push it visibly off.

    flush is what "right" means. Left to itself the stamp's right edge sits
    flush with the body text, which is what the automatic placement has always
    done and looks deliberate on an ordinary page. It is wrong for a position
    somebody picked: on a document with a narrow text column, flush-with-text
    puts "bottom right" almost exactly where "bottom left" goes, and a choice
    that does not move the stamp is not a choice. flush=False mirrors the
    page's own side margin instead, so left and right are the two sides of the
    page and always look it.
    """
    side = normalise_side(side)
    H, W = page.rect.height, page.rect.width
    gap = 18.0
    words = page.get_text("words")
    if not words:                       # nothing to measure against
        x0 = {"left": 54.0,
              "centre": (W - BOX_W) / 2,
              "right": W - BOX_W - 54}[side]
        return fit_to_page((x0, 54.0, x0 + BOX_W, 54.0 + BOX_H), page)

    right = min(max(w[2] for w in words), W - gap)      # content right margin
    left = min(w[0] for w in words)
    lowest = H - max(w[3] for w in words)               # clear band, from foot

    # The page's own side inset stands in for the bottom margin it would use;
    # documents are laid out with roughly even margins, and the foot of the
    # page carries nothing to measure directly.
    margin = min(max(left, gap), 90.0)

    # The stamp belongs in the footer white space, never on top of the body.
    # Sit on the page's own margin, but drop lower when the text reaches down
    # into it - a signature block near the foot is exactly that case. Taking
    # the lower of the two also keeps a sparse page's stamp at the bottom
    # rather than stranding it just under the only line of text.
    #
    # If the text runs so far down that even the bottom edge would clash, the
    # stamp still goes at the foot and the collision check says so: better a
    # flagged overlap you can see in --preview than a silent one.
    if side == "left":
        x0 = min(max(left, gap), W - BOX_W - gap)
    elif side == "centre":
        x0 = max((W - BOX_W) / 2, gap)
    elif flush:
        x0 = max(right - BOX_W, gap)
    else:
        x0 = max(W - margin - BOX_W, gap)
    y0 = max(min(margin, lowest - gap - BOX_H), gap)
    return fit_to_page((x0, y0, x0 + BOX_W, y0 + BOX_H), page)


def anchor_box(path, anchor, page_opt, side=DEFAULT_SIDE):
    """(page_index, (x0, y0, x1, y1)) in PDF coords, measured from bottom-left.

    PyMuPDF reports rectangles from the top-left, hence the flip.

    This is the anchor search only - corner placement is planned in
    place_document(), which is where a list of pages turns into a list of
    stamps. Where the anchor is not found this still falls back to a corner
    box, on `side`, so the fallback matches whatever was asked for.
    """
    doc = fitz.open(path)
    try:
        pages = range(doc.page_count)
        if page_opt not in (None, "", "auto"):
            wanted, _missing = parse_pages(page_opt, doc.page_count)
            pages = wanted

        for pno in pages:
            page = doc[pno]
            H, W = page.rect.height, page.rect.width
            found = page.search_for(anchor)
            if not found:
                continue
            # prefer the lowest occurrence: the signature block, not a mention
            # of the name in the body or a letterhead
            r = max(found, key=lambda r: r.y0)
            top = H - r.y0

            # Is this the RIGHT-hand column of a two-column signature block?
            # Decided structurally - is there other text on the same line to
            # its left - not by comparing x against half the page width. On a
            # letter-size page the second column often starts just left of
            # centre, which a width test gets wrong.
            band_lo, band_hi = r.y0 - 3, r.y1 + 3
            left_neighbour = any(
                w[3] > band_lo and w[1] < band_hi and w[2] < r.x0 - 20
                for w in page.get_text("words"))

            if left_neighbour:
                # stamp sits above the printed name, in its own column,
                # beside where the other party signs
                x0 = min(r.x0, W - BOX_W - 30)
                return pno, fit_to_page(
                    (x0, top + 4, x0 + BOX_W, top + 4 + BOX_H), page)

            # single/left column: stamp sits to the right of the name block
            x0 = max(r.x1 + 90, W / 2 + 14)
            x0 = min(x0, W - BOX_W - 40)
            return pno, fit_to_page(
                (x0, top - (BOX_H / 2 - 4), x0 + BOX_W,
                 top + (BOX_H / 2 + 4)), page)

        # The anchor was not found: corner of the page. "auto" means the FIRST
        # page here. A corner stamp is the document's signature, and that
        # belongs on page one; falling through to the last page only made
        # sense while this was an anchor-search fallback.
        wanted, _missing = parse_pages(page_opt, doc.page_count)
        pno = wanted[0] if wanted else 0
        return pno, corner_box(doc[pno], side)
    finally:
        doc.close()


# ------------------------------------------------- what a stamp must not hit
def obstacles(page):
    """Everything the stamp must stay off, as (rect, kind, label).

    Text alone is not enough, and the gap is dangerous rather than untidy: a
    scanned invoice has no extracted words at all, so a text-only check calls
    every position on the page clear and then stamps over the scan. Images,
    vector drawings and existing signature widgets all count.
    """
    out = []
    try:
        for wdg in page.widgets():
            if wdg.field_type == fitz.PDF_WIDGET_TYPE_SIGNATURE:
                out.append((fitz.Rect(wdg.rect), "signature",
                            "an existing signature"))
    except Exception:
        pass
    try:
        for info in page.get_image_info():
            out.append((fitz.Rect(info["bbox"]), "image", "an image"))
    except Exception:
        pass
    try:
        whole = page.rect.get_area() * 0.9
        for drawing in page.get_drawings():
            rect = fitz.Rect(drawing["rect"])
            if rect.get_area() >= whole:
                continue                # a page border or background wash
            # Ruling lines are not content. A table's rules and its cell
            # borders are stroke-only, and their rectangles span most of the
            # page - treating them as solid left almost nowhere free on any
            # ordinary invoice, so every such document got a signature page it
            # did not need. A stamp crossing a rule is what a wet signature
            # does anyway. Filled shapes are real ink and still count.
            if drawing.get("fill") is None:
                continue
            if rect.height < 3 or rect.width < 3:
                continue               # a hairline drawn as a filled sliver
            out.append((rect, "drawing", "a filled shape"))
    except Exception:
        pass
    for word in page.get_text("words"):
        out.append((fitz.Rect(word[:4]), "text", word[4]))
    return out


def obstacle_rects(page, limit=800):
    """Obstacles as (x0, y0, x1, y1, kind), in top-left points, merged.

    The same data blocking() uses, in the form the interface needs to test a
    box against while it is being dragged: top-left origin, because that is
    how the page is rendered and displayed, and merged along each line so the
    list is short enough to send.

    Words are merged only where they actually touch - a gap of more than a
    few points ends the run - so the space between two columns stays free.
    Merging a whole line into one rectangle would call that gap occupied, and
    the interface would report an overlap where the signer will not find one.
    """
    runs, other = {}, []
    for rect, kind, _label in obstacles(page):
        if kind != "text":
            other.append((rect.x0, rect.y0, rect.x1, rect.y1, kind))
            continue
        runs.setdefault(round(rect.y0 / 2.0), []).append(rect)

    merged = []
    for band in runs.values():
        band.sort(key=lambda r: r.x0)
        cur = None
        for rect in band:
            if cur and rect.x0 - cur[2] <= 3.0:
                cur[1] = min(cur[1], rect.y0)
                cur[2] = max(cur[2], rect.x1)
                cur[3] = max(cur[3], rect.y1)
            else:
                cur = [rect.x0, rect.y0, rect.x1, rect.y1]
                merged.append(cur)
    out = other + [(x0, y0, x1, y1, "text") for x0, y0, x1, y1 in merged]
    # A pathological page (a scan traced into thousands of glyph outlines)
    # would otherwise send a megabyte of rectangles for nothing.
    return [tuple(round(v, 1) if isinstance(v, float) else v for v in r)
            for r in out[:limit]]


def blocking(page, box, obs=None):
    """Human-readable labels for whatever a placement lands on; [] is clear."""
    H = page.rect.height
    rect = fitz.Rect(box[0], H - box[3], box[2], H - box[1])
    kinds, words = [], []
    for r, kind, label in (obstacles(page) if obs is None else obs):
        if not r.intersects(rect):
            continue
        if kind == "text":
            words.append(label)
        elif label not in kinds:
            kinds.append(label)
    if words:
        # Enough to recognise what is in the way, not a transcript of it - a
        # dense footer can match a hundred words.
        blob = " ".join(words[:6])
        kinds.append(blob if len(blob) <= 44 else blob[:41].rstrip() + "...")
    return kinds


def place_in_clear(page, side=DEFAULT_SIDE):
    """Where the stamp goes on this page, moved off obstacles if it must be.

    The chosen corner first, then sideways along the same band, then a band at
    a time upwards - nearest-first, so the stamp stays as close to where it
    belongs as the page allows. It never climbs out of the lower third; above
    that it stops looking like a signature and starts looking like vandalism.

    Returns (box, note). box is None when the page has no room at all.

    Only the automatic placement uses this. A position asked for outright is
    placed exactly there - see place_document().
    """
    obs = obstacles(page)
    first = corner_box(page, side)
    why = blocking(page, first, obs)
    if not why:
        return first, ""

    W, H = page.rect.width, page.rect.height
    gap, step_x, step_y = 18.0, 14.0, 10.0
    ceiling = H / 3.0
    x_start, y_bottom = first[0], first[1]

    # Candidate columns across the whole usable width, tried nearest to where
    # the stamp wanted to be first. Walking only leftwards from the text
    # margin was a bad miss: on a page whose text block is narrower than the
    # paper, the free space is to the RIGHT of that margin, and the scan never
    # looked there - so documents with plenty of room were handed a signature
    # page they did not need.
    x_max = max(W - gap - BOX_W, gap)
    columns, x = [], gap
    while x <= x_max:
        columns.append(x)
        x += step_x
    if x_max not in columns:
        columns.append(x_max)
    columns.sort(key=lambda c: abs(c - x_start))

    y = y_bottom
    while y <= ceiling:
        # Only obstacles overlapping this band can matter, and prefiltering
        # them keeps the scan quick on a text-heavy page.
        band_lo, band_hi = H - (y + BOX_H), H - y
        band = [o for o in obs if o[0].y1 > band_lo and o[0].y0 < band_hi]
        for cx in columns:
            box = fit_to_page((cx, y, cx + BOX_W, y + BOX_H), page)
            if not blocking(page, box, band):
                moved = []
                if round(y - y_bottom):
                    moved.append(f"up {y - y_bottom:.0f}pt")
                if round(cx - x_start):
                    side = "right" if cx > x_start else "left"
                    moved.append(f"{side} {abs(cx - x_start):.0f}pt")
                note = ("moved " + " and ".join(moved) + " to clear "
                        + why[0]) if moved else ""
                return box, note
        y += step_y
    return None, "no clear space on this page - " + why[0] + " is in the way"


def signature_page_doc(src, name=None):
    """The document with a signature page put in front, as a fitz document.

    Used by both the preview and the signing run, so what you are shown and
    what gets signed cannot drift apart. `name` is what the added page calls
    the document: the Word file's name where src is a converted copy of it,
    never the temp file's.
    """
    original = fitz.open(src)
    try:
        rect = original[0].rect
        out = fitz.open()
        page = out.new_page(width=rect.width, height=rect.height)
        name = name or os.path.basename(src)
        page.insert_text((72, 96), "Digital signature", fontsize=13)
        page.insert_text(
            (72, 124),
            "This page carries the digital signature for the document that",
            fontsize=9)
        page.insert_text((72, 138), f"follows: {name}", fontsize=9)
        page.insert_text(
            (72, 162),
            "It was added because that document had no clear space for a",
            fontsize=9)
        page.insert_text((72, 176),
                         "signature. Nothing in the original has been altered.",
                         fontsize=9)
        out.insert_pdf(original)
        return out
    finally:
        original.close()


class Row(tuple):
    """One planned signature: where it goes and how it got there.

    src is the PDF that is actually read and signed. origin is the file the
    user chose, which is the Word document when one was converted - every
    output name and every message comes from origin, so a temp path is never
    shown and "Report.docx" produces "Report - signed.pdf".
    """
    __slots__ = ()

    def __new__(cls, src, pno, box, note="", prepend=False, origin=None):
        return tuple.__new__(cls, (src, pno, box, note, prepend,
                                   origin or src))

    src = property(lambda self: self[0])
    pno = property(lambda self: self[1])
    box = property(lambda self: self[2])
    note = property(lambda self: self[3])
    prepend = property(lambda self: self[4])
    origin = property(lambda self: self[5])
    name = property(lambda self: os.path.basename(self[5]))


def plan(paths, anchor, page_opt, corner=False, side=DEFAULT_SIDE,
         exact=False, log=None):
    """Plan the signatures for a batch: one Row per stamp, not per document.

    Each item is either a path or a (pdf, origin) pair as Prepared.pairs
    hands them over - the pair form is what carries a Word document's own
    name through to the output. A document asked to be signed on several
    pages contributes several rows, in page order, and they are kept together
    so signing can put every one of them into the single output file.
    """
    say = log or print
    rows = []
    for item in paths:
        src, origin = item if isinstance(item, tuple) else (item, item)
        try:
            rows.extend(place_document(src, anchor, page_opt, corner, origin,
                                       side, exact))
        except Exception as exc:
            say(f"  cannot place on {os.path.basename(origin)}: {exc}")
    return rows


def place_document(src, anchor, page_opt, corner=False, origin=None,
                   side=DEFAULT_SIDE, exact=False):
    """Placements for one document, as a list of Rows - one per page stamped.

    exact is the difference between a position the program chose and one you
    chose. Without it, corner placement hunts for clear space and falls back
    to an added signature page, which is the right behaviour when nobody said
    where the stamp should go. With it, the stamp is put where it was asked
    for and nowhere else: a position that quietly moves is not a position you
    chose, and the overlap is reported instead of being designed around.
    """
    origin = origin or src
    if not corner:
        pno, box = anchor_box(src, anchor, page_opt, side)
        return [Row(src, pno, box, origin=origin)]

    side = normalise_side(side)
    doc = fitz.open(src)
    try:
        count = doc.page_count          # read before the document is closed
        pages, missing = parse_pages(page_opt, count)
        if not pages:
            raise ValueError(
                f"page {', '.join(str(m) for m in missing)} asked for, but "
                f"the document has {count}")
        # Only the single-page automatic case may grow a page: with several
        # pages planned, inserting one in front would renumber every other
        # placement in this document.
        may_prepend = not exact and len(pages) == 1
        rows = []
        for pno in pages:
            page = doc[pno]
            if exact:
                # flush=False: a chosen side is a side of the page, not of
                # the text block - see corner_box().
                rows.append(Row(src, pno, corner_box(page, side, flush=False),
                                origin=origin))
                continue
            box, note = place_in_clear(page, side)
            if box is not None:
                rows.append(Row(src, pno, box, note, origin=origin))
            elif may_prepend:
                # Nothing on the page is free. Put a signature page in front
                # and stamp that instead - it becomes page one, so the
                # signature still leads the document, and not a mark lands on
                # the original.
                composed = signature_page_doc(src, os.path.basename(origin))
                try:
                    rows.append(Row(
                        src, 0, corner_box(composed[0], side),
                        "no clear space - signing on an added first page",
                        True, origin))
                finally:
                    composed.close()
            else:
                rows.append(Row(src, pno, corner_box(page, side), note,
                                origin=origin))
    finally:
        doc.close()

    if missing and rows:
        skipped = (f"page{'s' if len(missing) > 1 else ''} "
                   f"{', '.join(str(m) for m in missing)} not in this "
                   f"{count}-page document")
        first = rows[0]
        rows[0] = Row(first.src, first.pno, first.box,
                      f"{skipped}; {first.note}" if first.note else skipped,
                      first.prepend, first.origin)
    return rows


def open_planned(row):
    """The document as it will be signed: composed when a page was added."""
    return (signature_page_doc(row.src, row.name) if row.prepend
            else fitz.open(row.src))


def rows_from_placements(pairs, placements, log=None):
    """Rows for boxes positioned by hand, rather than worked out from a rule.

    `placements` is [(origin, page number 1-based, box)] with the box in PDF
    coordinates, measured from the bottom left - what the signer wants. The
    interface hands these over after they have been dragged about on the
    preview, so nothing here is computed: the job is to check that each one
    still refers to a page that exists and sits on the paper, and to attach
    it to the PDF that will actually be signed.

    Everything is re-checked because the placement arrives over HTTP and
    because a Word document is converted afresh at signing time - a document
    edited between previewing and signing can have fewer pages than the
    placement was made against.
    """
    say = log or print
    by_origin = {origin: src for src, origin in
                 ((p if isinstance(p, tuple) else (p, p)) for p in pairs)}
    rows, seen = [], set()
    for origin, pageno, box in placements:
        src = by_origin.get(origin)
        if src is None:
            say(f"  ignoring a placement for a document that is not in this "
                f"selection: {os.path.basename(str(origin))}")
            continue
        doc = fitz.open(src)
        try:
            if not 1 <= pageno <= doc.page_count:
                say(f"  cannot place on {os.path.basename(origin)}: page "
                    f"{pageno} asked for, but the document has "
                    f"{doc.page_count}")
                continue
            page = doc[pageno - 1]
            x0, y0, x1, y1 = (float(v) for v in box)
            w, h = x1 - x0, y1 - y0
            # A box that arrived mangled gets the standard size at the corner
            # it asked for, rather than a stamp two points tall.
            if not (MIN_BOX_W <= w <= page.rect.width
                    and MIN_BOX_H <= h <= page.rect.height):
                w, h = BOX_W, BOX_H
            fitted = onto_page((x0, y0, x0 + w, y0 + h), page)
        finally:
            doc.close()
        if fitted is None:
            say(f"  cannot place on {os.path.basename(origin)}: that "
                f"position does not fit on page {pageno}")
            continue
        if (origin, pageno) in seen:
            continue                   # one stamp per page per document
        seen.add((origin, pageno))
        rows.append(Row(src, pageno - 1, fitted, "placed by hand",
                        origin=origin))
    return rows


def group_rows(rows):
    """[(origin, [rows])] - the stamps for each document, kept in page order.

    One document produces one output file however many pages it is stamped
    on, so signing works per document, not per stamp.
    """
    order, groups = [], {}
    for row in rows:
        if row.origin not in groups:
            order.append(row.origin)
            groups[row.origin] = []
        groups[row.origin].append(row)
    return [(origin, groups[origin]) for origin in order]


def collisions(row_or_src, pno=None, box=None):
    """Labels for whatever the stamp would land on. Empty means clear."""
    if isinstance(row_or_src, Row):
        row = row_or_src
    else:
        row = Row(row_or_src, pno, box)
    doc = open_planned(row)
    try:
        return blocking(doc[row.pno], row.box)
    finally:
        doc.close()


# ------------------------------------------------------------------- actions
def do_preview(rows, outdir):
    os.makedirs(outdir, exist_ok=True)
    print("Red box = where the signature will go.\n")
    bad = added = 0
    for row in rows:
        doc = open_planned(row)
        page = doc[row.pno]
        hits = blocking(page, row.box)
        H = page.rect.height
        page.draw_rect(fitz.Rect(row.box[0], H - row.box[3],
                                 row.box[2], H - row.box[1]),
                       color=(1, 0, 0), width=1.5)
        out = os.path.join(
            outdir, os.path.splitext(row.name)[0] + f"_p{row.pno+1}.png")
        page.get_pixmap(dpi=110).save(out)
        doc.close()
        # A document that got a signature page is "clear" only because of the
        # page that was added for it. Saying CLEAR there reads as "there was
        # room", which is the opposite of what happened.
        if row.prepend:
            flag = "PAGE ADDED"
            added += 1
        elif hits:
            flag = f"COLLIDES: {hits[:3]}"
            bad += 1
        else:
            flag = "CLEAR"
        print(f"  p{row.pno+1}  {row.name:<46} {flag}")
        if row.note:
            print(f"        {row.note}")
        print(f"        {out}")
    summary = f"\n{len(rows)} previewed, {bad} with collisions"
    if added:
        summary += f", {added} given a signature page"
    print(summary + ".")
    print(f"Previews in: {outdir}")
    return 1 if bad else 0


# --------------------------------------------------------- token, certificate
def candidate_modules(explicit=None):
    """PKCS#11 modules worth trying, most likely first.

    A new DSC provider usually means a new token and a new driver, so the
    curated list is only a head start: anything else in System32 that looks
    like a PKCS#11 module is tried after it. Names are filtered rather than
    loaded blind - the "_s" companions shipped beside several of these drivers
    export no C_GetFunctionList, and a few unrelated runtime DLLs (msvcp110
    and friends) match the glob by coincidence.
    """
    if explicit:
        return [(explicit, "given with --module")]
    out, seen = [], set()
    for name, who in KNOWN_MODULES:
        path = os.path.join(SYSTEM32, name)
        if os.path.isfile(path):
            seen.add(name.lower())
            out.append((path, who))
    for pat in ("*pkcs11*.dll", "*p11*.dll", "eps2003*.dll"):
        for path in glob.glob(os.path.join(SYSTEM32, pat)):
            name = os.path.basename(path).lower()
            if (name in seen or name.startswith("msvc")
                    or name.endswith("_s.dll")):
                continue
            seen.add(name)
            out.append((path, "found in System32"))
    return out


def scan_tokens(module=None, verbose=True):
    """Every slot, on every module, that reports a token present.

    [(module_path, slot_index, slot_id, token)]. This deliberately does not
    stop at the first hit: with several drivers installed, or two tokens
    plugged in, the first hit is not reliably the one you meant.

    slot_index and slot_id are not the same number and the difference bites.
    pyHanko's slot_no is a position in the list that lib.get_slots() returns,
    so the list must be enumerated UNFILTERED for that index to line up; the
    slot_id is the driver's own identifier for the reader, which is what a
    person reading the probe output would recognise.
    """
    from pyhanko.sign import pkcs11 as p11
    found = []
    for dll, who in candidate_modules(module):
        base = os.path.basename(dll)
        try:
            lib = p11.pkcs11.lib(dll)
            slots = list(lib.get_slots())
        except Exception as exc:
            if verbose:
                print(f"  {base:<26} {type(exc).__name__}: {exc}")
            continue
        hits = 0
        for index, slot in enumerate(slots):
            try:
                tok = slot.get_token()      # raises when the slot is empty
            except Exception:
                continue
            if tok is None:
                continue
            hits += 1
            found.append((dll, index, slot.slot_id, tok))
            if verbose:
                print(f"  {base:<26} TOKEN  slot={slot.slot_id} (index "
                      f"{index})  label={tok.label!r}  "
                      f"mfr={tok.manufacturer_id!r}")
        if not hits and verbose:
            print(f"  {base:<26} loaded, no token   ({who})")
    return found


def choose_token(found, want_label=None):
    """One (module, slot_index, slot_id, token), or None and the reason why."""
    if want_label:
        found = [f for f in found
                 if want_label.lower() in (f[3].label or "").lower()]
        if not found:
            print(f"\nNo token whose label contains {want_label!r}.")
            return None
    if not found:
        print("\nNo token found. Is it plugged in, and its driver installed?")
        print("If the driver is somewhere other than System32, point at it "
              "with --module PATH.")
        return None
    if len(found) > 1:
        print("\nMore than one token is present:")
        for dll, _index, slot_id, tok in found:
            print(f"   {(tok.label or ''):<24} {os.path.basename(dll)} "
                  f"slot {slot_id}")
        print("\nChoose one with --token LABEL, or --module PATH.")
        return None
    return found[0]


def pin_related(exc):
    """Whether a failed session open actually implicates the PIN.

    python-pkcs11 raises distinct classes for the PIN cases; everything else
    (a bad slot index, a driver that will not load, no token) fails before the
    PIN is ever sent.
    """
    names = {type(exc).__name__}
    cause = getattr(exc, "__cause__", None)
    if cause is not None:
        names.add(type(cause).__name__)
    if names & {"PinIncorrect", "PinLocked", "PinExpired", "PinInvalid",
                "PinLenRange", "UserAlreadyLoggedIn", "UserPinNotInitialized"}:
        return True
    text = f"{exc} {cause or ''}".lower()
    return "pin" in text


def subject_cn(cert):
    """The signatory's name.

    Company DSCs put the person in CN and the company in O, but a few
    certificate types (document signers, some departmental certificates) carry
    no CN at all, so fall back rather than ending up with a nameless stamp.
    """
    try:
        subj = cert.subject.native
    except Exception:
        return None
    return (subj.get("common_name") or subj.get("organizational_unit_name")
            or subj.get("organization_name"))


def subject_place(cert):
    """Where the certificate says its holder is, for the Location field."""
    try:
        subj = cert.subject.native
    except Exception:
        return None
    return (subj.get("locality_name") or subj.get("state_or_province_name")
            or None)


def subject_org(cert):
    """The organisation a company DSC is issued under, if any."""
    try:
        subj = cert.subject.native
    except Exception:
        return None
    org = subj.get("organization_name")
    # On a personal DSC the O is a filler like "Personal" or repeats the name;
    # neither is worth a line on the stamp.
    if not org or org.strip().lower() in ("personal", "individual"):
        return None
    if org.strip().lower() == (subject_cn(cert) or "").strip().lower():
        return None
    return org


def read_certs(tok, pin=None):
    """[(cka_id, label, certificate)] as stored on the token.

    Most Indian DSC tokens hand over their certificates without a login, which
    is what lets --probe, and the summary shown before signing, tell you whose
    certificate is about to be used. Some will not, hence the optional PIN.
    """
    from asn1crypto import x509
    from pkcs11 import Attribute, ObjectClass
    out = []
    sess = tok.open(user_pin=pin) if pin else tok.open()
    with sess:
        for obj in sess.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
            try:
                cert = x509.Certificate.load(obj[Attribute.VALUE])
            except Exception:
                continue
            try:
                cka_id = obj[Attribute.ID]
            except Exception:
                cka_id = None
            try:
                label = obj[Attribute.LABEL]
            except Exception:
                label = None
            out.append((cka_id, label, cert))
    return out


def split_certs(entries):
    """(signing candidates, CA chain, everything else).

    This split is the whole reason signing broke when the DSC provider
    changed. Handed no certificate to use, pyHanko asks the token for "the"
    certificate and insists on exactly one answer. A provider that puts only
    the leaf on the token satisfies that by luck; a provider that also loads
    the CA chain onto it makes the same query return four, and signing fails
    before it starts. So choose the leaf here and hand it over explicitly.
    """
    leaves, cas, others = [], [], []
    for cka_id, label, cert in entries:
        bc = cert.basic_constraints_value
        is_ca = bool(bc["ca"].native) if bc is not None else False
        ku = set(cert.key_usage_value.native) if cert.key_usage_value else set()
        if is_ca:
            cas.append((cka_id, label, cert))
        elif not ku or (ku & {"digital_signature", "non_repudiation"}):
            leaves.append((cka_id, label, cert))
        else:
            others.append((cka_id, label, cert))    # e.g. an encryption DSC
    return leaves, cas, others


def cert_line(cert):
    validity = cert["tbs_certificate"]["validity"]
    nb = validity["not_before"].native
    na = validity["not_after"].native
    expired = "   EXPIRED" if na < datetime.now(timezone.utc) else ""
    issuer = (cert.issuer.native.get("organization_name")
              or cert.issuer.native.get("common_name") or "?")
    return (f"{subject_cn(cert)}\n"
            f"              issued by {issuer}, valid "
            f"{nb.strftime('%d-%m-%Y')} to {na.strftime('%d-%m-%Y')}{expired}")


def pick_signing_cert(entries, want=None):
    """(cka_id, label, cert) for the certificate that should sign, and the
    CA certificates to embed alongside it. (None, []) if it is not decidable.
    """
    leaves, cas, others = split_certs(entries)
    if want:
        w = want.lower()
        leaves = [e for e in leaves
                  if w in (subject_cn(e[2]) or "").lower()
                  or w in (e[1] or "").lower()]
        if not leaves:
            print(f"\nNo signing certificate on this token matches "
                  f"--cert {want!r}.")
            return None, []
    if not leaves:
        print("\nThis token carries no certificate that can sign.")
        for _, _, c in others:
            print(f"    not usable for signing: {subject_cn(c)}")
        if cas:
            print(f"    ({len(cas)} CA certificate(s) present.)")
        return None, []
    if len(leaves) > 1:
        print("\nMore than one signing certificate on this token:")
        for _, _, c in leaves:
            print(f"    {cert_line(c)}")
        print('\nChoose one with --cert "PART OF THE NAME".')
        return None, []
    return leaves[0], [c for _, _, c in cas]


def fit_line(text, width=None):
    """Break one line to the stamp width, on spaces where there are any.

    pyHanko's text boxes do not word-wrap and the box is a fixed size, so
    anything too long would simply run out of the frame. Company names are the
    usual offender - they are routinely longer than a person's name.

    width is read at call time, not bound at import, so changing STAMP_COLS
    beside the box dimensions actually changes the wrapping.
    """
    width = width or STAMP_COLS
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
        while len(cur) > width:            # a single word longer than the box
            lines.append(cur[:width])
            cur = cur[width:]
    if cur:
        lines.append(cur)
    return lines or [""]


def stamp_style(cert, place, designation=None, mark_style=MARK_STYLE,
                token=None):
    """The signature appearance: the wording, and the mark behind it."""
    from pyhanko import stamp
    from pyhanko.pdf_utils import layout
    from pyhanko.pdf_utils import text as pdftext

    # The seal stands at full height on the right, so the text has about 40pt
    # less room than the other styles - and the one line that cannot be
    # wrapped out of trouble is the date, because a date broken in half looks
    # like a defect. A point smaller is what buys it that room in a 150pt box;
    # the other styles run the text over the mark and need nothing.
    font = STAMP_FONT - 1 if mark_style == "seal" else STAMP_FONT

    kwargs = {}
    path = MARK_FILES.get(mark_style or "none")
    if path and os.path.isfile(path):
        from pyhanko.pdf_utils.images import PdfImage
        if mark_style == "seal":
            # right-aligned, text running clear of it
            # The badge is square and inset top and bottom, so this padding is
            # what sets its width, and its width is what the date line has to
            # clear. SEAL_PAD is the number to change if the seal ever starts
            # sitting on the text again.
            rule = layout.SimpleBoxLayoutRule(
                x_align=layout.AxisAlignment.ALIGN_MAX,
                y_align=layout.AxisAlignment.ALIGN_MID,
                margins=layout.Margins(right=MARK_PAD, top=SEAL_PAD,
                                       bottom=SEAL_PAD),
                inner_content_scaling=layout.InnerScaling.STRETCH_TO_FIT)
        else:
            # cover and band both fill the whole stamp
            rule = layout.SimpleBoxLayoutRule(
                x_align=layout.AxisAlignment.ALIGN_MID,
                y_align=layout.AxisAlignment.ALIGN_MID,
                inner_content_scaling=layout.InnerScaling.STRETCH_FILL)
        kwargs = {
            "background": PdfImage(path),
            "background_opacity": MARK_OPACITY.get(mark_style, 0.20),
            "background_layout": rule,
        }
    text, name_lines = stamp_lines(cert, designation, token)
    return highlighted_style()(
        stamp_text=text,
        border_width=1,
        text_box_style=pdftext.TextBoxStyle(font_size=font),
        lit_lines=tuple(name_lines),
        lit_colour=NAME_COLOUR,
        **kwargs)


_LIT_STYLE = []             # built once, on the first signature of a run


def highlighted_style():
    """A TextStampStyle that draws named lines in colour, others in black.

    pyHanko colours a text box as a whole - TextBoxStyle.text_color - and the
    signatory's name is one line inside it, so the colour has to be injected
    between lines instead. Every line of the rendered box is a self-contained
    run of operators that TextBox.put_string_line() will reproduce exactly, so
    the name's own run can be found in the finished stream and wrapped in a
    fill-colour operator and a reset. That means no copy of pyHanko's layout
    code here: it renders the box, and this puts colour around one line of it.

    If a future pyHanko renders lines differently the run simply will not be
    found, and the stamp comes out in plain black - never a failed signature.

    Built lazily and cached: pyHanko is a slow import, and the command line
    probes tokens and previews placements without ever needing it.
    """
    if _LIT_STYLE:
        return _LIT_STYLE[0]

    from dataclasses import dataclass, field
    from pyhanko.stamp import TextStamp, TextStampStyle

    class LitNameStamp(TextStamp):
        def _text_layout(self):
            stream = super()._text_layout()
            box, style = self.text_box, self.style
            if box is None or not style.lit_lines or not style.lit_colour:
                return stream           # NAME_COLOUR = None: plain black
            on = b'%g %g %g rg ' % tuple(style.lit_colour)
            for line in style.lit_lines:
                try:
                    ops, _extent = box.put_string_line(line)
                except Exception:
                    continue            # never fail a signature over colour
                if ops and ops in stream:
                    stream = stream.replace(ops, on + ops + b' 0 g', 1)
            return stream

    @dataclass(frozen=True)
    class LitNameStampStyle(TextStampStyle):
        lit_lines: tuple = ()
        lit_colour: tuple = field(default_factory=lambda: NAME_COLOUR)

        def create_stamp(self, writer, box, text_params):
            return LitNameStamp(writer=writer, style=self, box=box,
                                text_params=text_params)

    _LIT_STYLE.append(LitNameStampStyle)
    return LitNameStampStyle


def signed_by_line(token=None):
    """The stamp's first line: which token did the signing.

    A token label rather than a bare "Digitally signed by", because the label
    is the one thing on the stamp that says which piece of hardware the key
    lives on - and the reader may hold several. The serial number is
    deliberately left out: it identifies the device, not the signatory, and
    the stamp is already the width of one line of type.

    PKCS#11 pads labels out to 32 characters with spaces, so it is stripped
    before use; a driver that returns nothing useful falls back to the old
    wording rather than printing " sign by".
    """
    label = (token or "").strip()
    return f"{label} sign by" if label else "Digitally signed by"


def stamp_lines(cert, designation=None, token=None):
    """(stamp text, the lines the signatory's name occupies).

    Everything on the stamp comes out of the certificate and the token and
    nothing else. It used to carry a hard-coded name, membership number and
    place, none of which the signature can vouch for, and all of which were
    wrong the moment a different DSC was inserted. The stamp now asserts only
    what the certificate itself asserts, above the label of the token the key
    is on.

    The name's lines are handed back separately because they are the ones
    drawn in colour - a long name wraps, so it is not reliably one line, and
    matching on the text afterwards would be guesswork.

    --designation still lets you set the second line by hand for a document
    that needs it; left alone, it is the organisation named in the certificate.
    """
    cn = subject_cn(cert) or "the certificate holder"
    if designation is None:
        designation = subject_org(cert)
    name = fit_line(cn.upper())
    lines = fit_line(signed_by_line(token)) + name
    if designation:
        lines += fit_line(designation)
    lines.append("Date: %(ts)s")
    return "\n".join(lines), name


def stamp_text_for(cert, designation=None, token=None):
    """The visible stamp as text - what --probe and the page show you."""
    return stamp_lines(cert, designation, token)[0]


def warn_if_unexpected(cert, anchor):
    """Show what the stamp will actually read, so a swapped token is obvious.

    There is no list of expected names to check against - that would be an
    outside reference, and the stamp deliberately has none. The certificate's
    own name is simply put in front of you before the PIN prompt.
    """
    cn = (subject_cn(cert) or "").strip()
    print(f"\n  The stamp will read {cn.upper()!r}.")
    if anchor and anchor.lower() not in cn.lower():
        print(f"  Placement is anchored to {anchor!r} - pass "
              f'--anchor "{cn}" if the stamp\n  should go by this '
              f"signatory's printed name instead.")


def signer_name(module=None, want_label=None, want_cert=None):
    """The name on the inserted token's certificate, or None.

    Used as the default anchor: the printed name a stamp should sit beside is
    the signatory's own, and the certificate is the only place that is written
    down. Needs no PIN on the tokens seen so far; if it cannot be read, the
    caller falls back to corner placement.
    """
    try:
        chosen = choose_token(scan_tokens(module, verbose=False), want_label)
        if not chosen:
            return None
        picked, _chain = pick_signing_cert(read_certs(chosen[3]), want_cert)
        return subject_cn(picked[2]) if picked else None
    except Exception:
        return None


def do_probe(module=None, want_label=None, want_cert=None):
    print("Probing PKCS#11 modules:\n")
    chosen = choose_token(scan_tokens(module), want_label)
    if not chosen:
        return 1
    dll, slot_index, slot_id, tok = chosen
    serial = tok.serial
    if isinstance(serial, bytes):
        serial = serial.decode("ascii", "replace")
    print(f"\nModule : {dll}")
    print(f"Token  : {tok.label!r}   slot {slot_id} (index {slot_index}), "
          f"serial {serial}")

    # Reading the certificates is the part that actually predicts whether
    # --sign will work. The probe used to stop at "a token is present", which
    # is why a change of provider only ever showed up at signing time.
    try:
        entries = read_certs(tok)
    except Exception as exc:
        print(f"\nCertificates are not readable without the PIN "
              f"({type(exc).__name__}: {exc}).")
        print("Run --sign to check them.")
        return 0
    if not entries:
        print("\nNo certificates are readable without the PIN. "
              "Run --sign to check them.")
        return 0

    leaves, cas, others = split_certs(entries)
    print(f"\nCerts  : {len(entries)} on the token - {len(leaves)} signing, "
          f"{len(cas)} CA, {len(others)} other")
    picked, _chain = pick_signing_cert(entries, want_cert)
    if not picked:
        return 1
    print(f"\nWill sign as : {cert_line(picked[2])}")
    warn_if_unexpected(picked[2], None)
    return 0


def do_sign(rows, anchor, reason, place, suffix, tsa,
            module=None, want_label=None, want_cert=None, designation=None,
            mark_style=MARK_STYLE):
    print("Probing for the token:\n")
    chosen = choose_token(scan_tokens(module), want_label)
    if not chosen:
        return 1
    dll, slot_index, _slot_id, tok = chosen

    # Settle on the certificate before asking for the PIN wherever the token
    # allows it, so the signatory is on screen while there is still a way out.
    picked, chain, deferred = None, [], False
    try:
        entries = read_certs(tok)
    except Exception:
        entries = []
    if entries:
        picked, chain = pick_signing_cert(entries, want_cert)
        if not picked:
            return 1
    else:
        deferred = True

    docs = group_rows(rows)
    print(f"\n{len(docs)} document(s), {len(rows)} signature(s), with the "
          f"certificate on {tok.label!r}:")
    warn = 0
    for _origin, group in docs:
        for row in group:
            hits = collisions(row)
            mark = "" if not hits else "   <-- OVERLAPS, run --preview"
            if hits:
                warn += 1
            print(f"   p{row.pno+1}  {row.name}{mark}")
            if row.note:
                print(f"         {row.note}")
    if warn:
        # The stamp is drawn on top of the page: whatever is under it stays in
        # the file but stops being readable. That is a separate decision from
        # "sign these documents", so it is asked as a separate question rather
        # than folded into the proceed prompt.
        print(f"\n{warn} signature(s) would be drawn over existing content "
              f"and may hide text.")
        if input("Place them over it anyway? [y/N] ").strip().lower() != "y":
            print("Aborted. Nothing written. Change --page or --corner-side, "
                  "or run --preview to see the overlap.")
            return 1
    if picked:
        print(f"\nCertificate : {cert_line(picked[2])}")
        warn_if_unexpected(picked[2], anchor)
    else:
        print("\nThis token will not show its certificate without the PIN; "
              "you will be\nasked to confirm the signatory after entering it.")
    if tsa:
        print(f"\nTIMESTAMP: {tsa}  -- this makes a network call per signature.")
    else:
        print("\nFully offline: no timestamp, no revocation checks.")

    if input("\nProceed? [y/N] ").strip().lower() != "y":
        print("Aborted. Nothing written.")
        return 1

    pin = getpass.getpass("Token PIN (not echoed, not stored): ")

    if deferred:
        try:
            entries = read_certs(tok, pin)
        except Exception as exc:
            print(f"\nCould not read the token's certificates: "
                  f"{type(exc).__name__}: {exc}")
            print("A wrong PIN is the usual cause. Repeated wrong PINs can "
                  "lock the token, so check before retrying.")
            return 1
        picked, chain = pick_signing_cert(entries, want_cert)
        if not picked:
            return 1
        print(f"\nCertificate : {cert_line(picked[2])}")
        warn_if_unexpected(picked[2], anchor)
        if input("\nSign with this certificate? [y/N] ").strip().lower() != "y":
            print("Aborted. Nothing written.")
            return 1

    results, err = sign_documents(rows, dll, slot_index, tok, picked, chain,
                                  pin, reason, place, suffix, tsa, designation,
                                  log=print, mark_style=mark_style)
    pin = None
    if err:
        print(f"\nCould not open a signing session: {err}")
        # Only raise the PIN alarm when the PIN is actually implicated. Saying
        # "wrong PIN" after a slot or driver error sends you off checking a
        # PIN that was never submitted, and invites a needless retry on a
        # token that locks after a few of them.
        if pin_related(err):
            print("A wrong PIN is the usual cause. Repeated wrong PINs can "
                  "lock the token, so check before retrying.")
        else:
            print("This failed before the PIN was submitted, so no attempt "
                  "was used against the token.")
        return 1

    print(f"\n{'FILE':<50} {'BYTES':>10} {'SIGS':>5}  RESULT")
    print("-" * 78)
    checked = verify_outputs(results)
    bad = 0
    for name, size, nsigs, good, err in checked:
        if not good:
            bad += 1
            print(f"{name:<50} {'-' if size is None else format(size, ','):>10} "
                  f"{'-' if nsigs is None else nsigs:>5}  FAIL  {err[:30]}")
        else:
            print(f"{name:<50} {size:>10,} {nsigs:>5}  PASS")
    print("-" * 78)
    print(f"{len(checked)} file(s): {len(checked)-bad} signed and verified, "
          f"{bad} failed")
    return 1 if bad else 0


def verify_outputs(results):
    """Reopen each output and confirm a signature really is embedded.

    [(name, size, n_signatures, ok, error)]. Signing reporting success is not
    the same as the file carrying a signature, so this is a separate pass.
    """
    from pyhanko.pdf_utils.reader import PdfFileReader
    checked = []
    for _src, dst, ok, err in results:
        name = os.path.basename(dst)
        if not ok:
            checked.append((name, None, None, False, err))
            continue
        try:
            # Verify leniently for the same reasons the writer does; a strict
            # reader refuses these files and would report a real signature as
            # absent.
            with open(dst, "rb") as fh:
                n = len(PdfFileReader(fh, strict=False).embedded_signatures)
            checked.append((name, os.path.getsize(dst), n, n >= 1,
                            "" if n >= 1 else "no signature found"))
        except Exception as exc:
            checked.append((name, None, None, False,
                            f"{type(exc).__name__}: {exc}"))
    return checked


def sign_documents(rows, dll, slot_index, tok, picked, chain, pin,
                   reason, place, suffix, tsa=None, designation=None,
                   log=None, mark_style=MARK_STYLE):
    """Sign every row with the already-resolved certificate. No console I/O.

    Returns (results, error): results is [(src, dst, ok, err)] per document,
    and error is set only when the signing session could not be opened at all,
    in which case nothing was written. The command line and the local web
    interface both call this, so there is one signing implementation.
    """
    from pyhanko.config.pkcs11 import TokenCriteria
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko.sign.fields import SigFieldSpec, append_signature_field
    from pyhanko.sign.pkcs11 import PKCS11SignatureConfig, PKCS11SigningContext

    say = log or (lambda *a: None)
    cka_id, _cert_label, signing_cert = picked
    # Taken off the certificate unless the caller insisted otherwise.
    if place is None:
        place = subject_place(signing_cert)
    # tok.label is what the stamp's first line names - see signed_by_line().
    style = stamp_style(signing_cert, place, designation, mark_style,
                        getattr(tok, "label", None))

    # Name the slot as well as the token: two tokens from the same vendor
    # carry the same label, and the label alone would then be ambiguous.
    # slot_no is pyHanko's index into lib.get_slots(), not the driver's slot
    # id - scan_tokens() records the index for exactly this call.
    # Handing over the certificate and the matching key id is what keeps this
    # working across providers - see split_certs().
    cfg = PKCS11SignatureConfig(module_path=dll,
                                slot_no=slot_index,
                                token_criteria=TokenCriteria(label=tok.label),
                                signing_certificate=signing_cert,
                                key_id=cka_id,
                                other_certs=chain,
                                other_certs_to_pull=(),
                                user_pin=pin)
    timestamper = None
    if tsa:
        from pyhanko.sign.timestamps import HTTPTimeStamper
        timestamper = HTTPTimeStamper(tsa)

    results = []
    try:
        with PKCS11SigningContext(cfg) as signer:

            def sign_one(signer_ctx, in_path, out_path, row, quiet):
                """One visible signature, from in_path to out_path."""
                with open(in_path, "rb") as fh:
                    # Real-world PDFs are routinely not strictly conformant.
                    # Two cases show up constantly:
                    #   - a malformed free-entry chain in the xref table,
                    #     which makes a strict open raise outright;
                    #   - hybrid cross-reference sections, which Word's PDF
                    #     export writes for backwards compatibility. These
                    #     open fine but pyHanko refuses to SIGN them while the
                    #     reader is strict.
                    # Try strict first so anything genuinely odd stays
                    # visible, then fall back for either reason.
                    why = None
                    try:
                        w = IncrementalPdfFileWriter(fh)
                        if w.prev.xrefs.hybrid_xrefs_present:
                            why = "hybrid cross-reference sections"
                    except Exception as strict_exc:
                        why = type(strict_exc).__name__
                    if why:
                        fh.seek(0)
                        w = IncrementalPdfFileWriter(fh, strict=False)
                        if not quiet:
                            say(f"  note: {row.name} opened leniently ({why})")
                    field = "DSC_" + os.urandom(4).hex()
                    append_signature_field(w, SigFieldSpec(
                        sig_field_name=field, box=row.box, on_page=row.pno))
                    meta = signers.PdfSignatureMetadata(
                        field_name=field, reason=reason, location=place,
                        embed_validation_info=False, use_pades_lta=False)
                    pdf_signer = signers.PdfSigner(
                        meta, signer=signer_ctx, stamp_style=style,
                        timestamper=timestamper)
                    with open(out_path, "wb") as out:
                        pdf_signer.sign_pdf(w, output=out)

            for origin, group in group_rows(rows):
                # Named off the file the user chose, not off the PDF being
                # read: Report.docx has to produce "Report - signed.pdf" in
                # its own folder, never something in the temp folder.
                dst = os.path.splitext(origin)[0] + suffix + ".pdf"
                lead = group[0]
                temps = []
                try:
                    source = lead.src
                    if lead.prepend:
                        # Sign the composed document, not the original. The
                        # original is never written to; this staging copy is
                        # deleted whatever happens.
                        fd, staged = tempfile.mkstemp(suffix=".pdf",
                                                      prefix="sign_dsc_")
                        os.close(fd)
                        temps.append(staged)
                        composed = signature_page_doc(lead.src, lead.name)
                        try:
                            composed.save(staged)
                        finally:
                            composed.close()
                        say(f"  note: {lead.name} had no clear "
                            f"space; a signature page was added in front")
                        source = staged
                    if len(group) > 1:
                        say(f"  {lead.name}: {len(group)} signatures, pages "
                            + ", ".join(str(r.pno + 1) for r in group))
                    # Each page is signed in turn, every pass reading the
                    # output of the one before it, so the signatures
                    # accumulate incrementally in one file - the same thing
                    # that happens when an already-signed document is signed
                    # again. Only the last pass writes to dst, so a failure
                    # part way through leaves the intermediate work in the
                    # temp folder and no half-signed output beside the
                    # original.
                    for i, row in enumerate(group):
                        if i == len(group) - 1:
                            out_path = dst
                        else:
                            fd, out_path = tempfile.mkstemp(suffix=".pdf",
                                                            prefix="sign_dsc_")
                            os.close(fd)
                            temps.append(out_path)
                        sign_one(signer, source, out_path, row, quiet=i > 0)
                        source = out_path
                    results.append((origin, dst, True, ""))
                except Exception as exc:
                    if os.path.isfile(dst):
                        os.remove(dst)
                    results.append((origin, dst, False,
                                    f"{type(exc).__name__}: {exc}"))
                    # Carry on with the rest of the batch. The partial output
                    # for this one is already removed, and the summary reports
                    # every failure.
                    say(f"  FAILED {lead.name}: "
                        f"{type(exc).__name__}: {exc}")
                    continue
                finally:
                    for path in temps:
                        if os.path.isfile(path):
                            try:
                                os.remove(path)
                            except OSError:
                                pass
    except Exception as exc:
        return [], exc
    finally:
        pin = None
    return results, None


def main():
    module = arg("--module")
    want_label = arg("--token")
    want_cert = arg("--cert")
    # None means "look the designation up from the certificate"; an explicit
    # empty --designation "" means "no qualification line at all".
    designation = arg("--designation")

    if "--probe" in sys.argv:
        return do_probe(module, want_label, want_cert)

    anchor = arg("--anchor", DEFAULT_ANCHOR)
    page_opt = arg("--page", "auto")
    # A side asked for outright is honoured exactly - see place_document().
    side_opt = arg("--corner-side")
    try:
        side = normalise_side(side_opt) if side_opt else DEFAULT_SIDE
    except ValueError as exc:
        print(exc)
        return 1
    exact = side_opt is not None
    reason = arg("--reason", REASON)
    place = arg("--place", PLACE)
    suffix = arg("--suffix", SUFFIX)
    tsa = arg("--tsa")

    paths = collect_inputs(sys.argv)
    if not paths:
        print(__doc__)
        return 0

    corner = "--corner" in sys.argv or exact
    if not corner and not anchor:
        # No anchor given, so take the signatory's name off the token. If the
        # token cannot be read, corner placement is the sane fallback - better
        # than anchoring to a name nobody here has any business assuming.
        anchor = signer_name(module, want_label, want_cert)
        if anchor:
            print(f"Anchoring to the name on the certificate: {anchor!r}\n")
        else:
            corner = True
            print(f"No --anchor and no readable certificate; placing in the "
                  f"bottom-{side} corner.\n")

    mark_style = arg("--mark-style", MARK_STYLE)
    if "--sign" in sys.argv and mark_style not in tuple(MARK_FILES) + ("none",):
        print(f"Unknown --mark-style {mark_style!r}. Use one of: "
              f"{', '.join(tuple(MARK_FILES) + ('none',))}")
        return 1

    # Word documents become temporary PDFs for the duration of this block and
    # are deleted on the way out of it - including when signing raises.
    with converted(paths, log=print) as prep:
        for src, why in prep.failed:
            print(f"  cannot convert {os.path.basename(src)}: {why}")
        if prep.failed:
            print()
        rows = plan(prep.pairs, anchor, page_opt, corner, side, exact)
        if not rows:
            print("Nothing to do.")
            return 1
        # A document that never got as far as being planned is a failure of
        # the run, whatever happens to the rest.
        rc = 1 if prep.failed else 0

        if "--preview" in sys.argv:
            outdir = os.path.join(os.path.dirname(os.path.abspath(paths[0])),
                                  "_signature_preview")
            return do_preview(rows, outdir) or rc
        if "--sign" in sys.argv:
            return do_sign(rows, anchor, reason, place, suffix, tsa,
                           module=module, want_label=want_label,
                           want_cert=want_cert, designation=designation,
                           mark_style=mark_style) or rc

        if corner:
            print(f"Placement: bottom-{side} of the page"
                  + (", exactly there - nothing is moved to avoid content\n"
                     if exact else "\n"))
        else:
            print(f"Anchor: {anchor!r}\n")
        for row in rows:
            hits = collisions(row)
            box = row.box
            print(f"  p{row.pno+1}  {row.name:<48} "
                  f"box=({box[0]:.0f},{box[1]:.0f})-({box[2]:.0f},{box[3]:.0f})"
                  f"{'' if not hits else '   OVERLAPS'}")
            if row.note:
                print(f"        {row.note}")
        print("\nAdd --preview to render PNGs, or --sign to sign.")
        return rc


if __name__ == "__main__":
    raise SystemExit(main())

