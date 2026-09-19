# DSCSigner
Token based digital signature on PDFs without requiring bulky GB softwares
[README.md](https://github.com/user-attachments/files/32408102/README.md)
# DSC Signer

*From the makers of Deccan Stat Books.*

Sign a folder of PDFs — or Word documents — with an Indian DSC token, offline,
from one prompt for the PIN.

Adobe Reader signs one file at a time and wants a gigabyte of disk. This does
a whole batch, weighs about 77 MB, installs nothing, runs no background
service, and asks for no account. Nothing it does touches the internet: no
timestamp authority, no CRL or OCSP fetch, no telemetry. The private key never
leaves the token.

Originals are never modified. Each signed file is written alongside its
source as `<name> - signed.pdf`.

---

## Word documents

Hand it a `.docx`, `.doc`, `.docm` or `.rtf` and it converts before signing —
no separate export step. **Word itself does the conversion**, through the same
export as *File > Save as PDF*, so the pagination, the fonts and the layout are
what you would have got by hand. Word must be installed on the machine.

The converted PDF is temporary and is deleted when the run ends: the only new
file beside `Report.docx` is `Report - signed.pdf`. The document is opened
read-only, macros are disabled for the conversion, and a private instance of
Word is used rather than the copy you have open — quitting yours, with your
unsaved work in it, is not on the table.

Nothing is cached between operations. Previewing and then signing converts
twice, which costs a few seconds and means what gets signed is the document as
it stands when you sign it, not as it stood when you previewed it.

If Word cannot open something, that document is reported by name with Word's
own explanation, and everything else in the same batch is still signed.

---

## Running it

**The packaged build.** `DSC Signer.exe` is on the
[Releases](../../releases) page — it is not in the repository, because it is
rebuilt from this source and a 77 MB binary does not belong in version
history.

Download it, put it on a local disk, and run it. There is nothing to install:
Python and every library are inside the one file. A browser opens on a page
served from `127.0.0.1`. Keep the console window — it prints the address, and
it is where you stop the server.

The only things it needs from the machine are your token's PKCS#11 driver,
which the token's own software installs, and Microsoft Word, and that only if
you hand it Word documents.

> Run it from a local drive. On a mapped network drive it can take minutes to
> start, or fail to start at all, because it unpacks itself on each launch.

**From source.**

```
pip install pyhanko pymupdf python-pkcs11 pillow pywin32
python sign_dsc_ui.py          # the interface
python sign_dsc.py --probe     # command line: what token is inserted?
```

`pywin32` is only needed for Word documents; without it PDFs still sign and a
Word file is reported as one that could not be prepared.

The command line has more control than the interface does - anchored
placement, timestamps. Run `python sign_dsc.py` with no arguments for the full
list. Pages and position are offered in both: `--page 1,3` and
`--corner-side centre` on the command line, the two boxes at the top of step 3
in the interface.

## What it does

0. **Converts anything that is not already a PDF**, with Word, into a
   temporary PDF that is deleted afterwards. See
   [Word documents](#word-documents).
1. **Finds the token.** Every PKCS#11 driver in `System32` is tried, not just
   a fixed list, and every slot on every driver.
2. **Picks the right certificate.** Tokens often carry the CA chain beside the
   signing certificate. The signing one is chosen explicitly - the leaf that
   is not a CA and carries a signing key usage - and the private key is pinned
   by its `CKA_ID`, so a token holding a separate encryption key pair cannot
   confuse it.
3. **Places the stamp** where you asked for it: the pages you named - `1`,
   `1,3`, `2-5`, `all`, `first`, `last` - at the bottom left, centre or right
   of each of them, on the page's own margins. Every page named gets its own
   stamp and its own signature, all inside the one signed PDF.
4. **Leaves it exactly there.** A position you chose is not moved aside to
   avoid what is already on the page - a stamp that wanders is not a position
   you chose. Instead the overlap is named in the preview and put in front of
   you again, to be confirmed, before the PIN is asked for. The stamp is drawn
   on top of the page, so where it lands on text it will hide it. Where the
   rule does not suit a particular document, drag the box on the preview and
   put it where it belongs - see [Preview before you sign](#preview-before-you-sign).
   (Left to itself - `--corner` with no side, or no placement given at all -
   the stamp still hunts for clear space and says why it moved: *"moved up
   34pt to clear an existing signature"*, and a page with no room at all gets
   a signature page in front rather than a stamp over the document.)
5. **Asks for the PIN in a desktop dialog**, never in the browser. See
   [Security](#security).
6. **Verifies its own work** - each output is reopened and checked to carry a
   signature before it is reported as done.

Everything on the visible stamp comes from the certificate or the token
itself: the signatory's name, the organisation, the date, and a first line
naming the token that signed - *"mToken CryptoID sign by"*. Nothing is
asserted that the signature cannot support.

## Preview before you sign

`Preview placement` renders each page with the signature box drawn over it and
reports anything it would land on. Do this for any document shape you have not
signed before - and do it again after changing the pages or the position,
because the position is honoured exactly and nothing will move to save you.
Signing asks you to confirm the overlap first; if the selection was never
previewed with these settings, it says that instead of pretending to know.

**Drag the box.** The preview is not a picture of the decision, it is the
decision: pick the box up with the mouse and put the signature anywhere on the
page - beside a printed name, in a margin, wherever it belongs on that
particular document. It turns green where it is clear of everything on the
page and red where it is not, as you move it. Arrow keys nudge it a point at a
time, `Shift` ten. *Use this spot on all* copies the position you just set
onto every other document in the batch, and *Reset* puts one back where the
program had it.

What is on screen when you press Sign is what gets signed - those exact
boxes, not the left/centre/right rule they started from. Change the pages or
the position afterwards and the boxes no longer describe what you are looking
at, so they are discarded and the rule applies again; the confirmation says so
before the PIN is asked for.

One limitation worth knowing: the check finds text, images, vector fills and
existing signature fields. It does not read the *meaning* of a page. A stamp
placed in genuinely empty space can still be in a place you would rather it
were not.

## Security

- **The PIN is never typed into the browser.** It is taken in a desktop
  dialog raised by the application itself. A password box in a web page is
  something the browser offers to save and sync to a cloud account, and
  `autocomplete="off"` does not prevent that - Chrome and Edge deliberately
  ignore it on password fields. The PIN is held in memory for the one signing
  session and dropped. It is never written, logged, or put in a URL.
- The server binds `127.0.0.1` only, on a random port, and every request must
  carry a random per-session key. The `Host` header is checked. Request
  logging is off.
- A signature made without `--tsa` carries this machine's clock rather than a
  trusted time. That is normal for offline signing and is accepted for
  departmental filings, but it is worth knowing.

## Which tokens are known to work

**Two vendors, proven against real tokens and real documents:**

| Token | Driver |
|---|---|
| ePass2003 / HYP2003 (two DSCs) | `eps2003csp11v2.dll` |
| mToken CryptoID (Longmai) | `CryptoIDA_pkcs11.dll` |

Everything else in `KNOWN_MODULES` is listed on reasonable grounds but has not
been proven against a real token, and no other vendor's token has been tried.

That does not mean yours will not work. The module list is only a head start:
any PKCS#11 driver in `System32` is discovered automatically, and `--module`
points at one anywhere else. A token from an unfamiliar provider stands a fair
chance of simply working. Run `--probe` to see what your machine exposes.

If it does not work, the source is here and the fix is usually one line in
`KNOWN_MODULES` in `sign_dsc.py`.

**If that is not your line of work**, hand `sign_dsc.py` to an AI assistant
and ask it to add support for your vendor's token. It is a short list to
extend and a well-defined problem.

> Give it to a **capable** assistant. This is not a task where a weak model
> saves you anything - it will loop, guess at driver names, and hand back
> changes that look plausible and do nothing. Use a strong model, give it the
> output of `--probe` from your machine, and tell it what token you have.

## Credits

> Designed by Deccan Stat Books in Pune. Assembled by Claude in a datacentre.

Copyright rests with **Deccan Stat Books**, who made every call about what
this should do and refuse to do, and who tested it against real tokens and
real documents.

The code was written with **Claude** (Anthropic). Worth being straight about
what that means: an AI assistant is a tool, not an author. It holds no
copyright and carries no responsibility for what the program does. Someone has
to hold the copyright for the AGPL to mean anything — a licence is a grant of
rights, and only a rights-holder can grant them.

Several of the sharper decisions here came from the human noticing something
wrong and pushing back: the browser's password manager reaching for the token
PIN, a signature page being added to documents that had ample room, and a
stamp asserting a name and a place the certificate never claimed. Those were
caught by use, not by cleverness.

## Licence

AGPL-3.0. See [`LICENSE`](LICENSE) and
[`THIRD-PARTY-NOTICES.txt`](THIRD-PARTY-NOTICES.txt), which explains why -
PyMuPDF is AGPL unless you hold Artifex's commercial licence, and that reaches
the whole application.

If you pass the executable to anyone, they are entitled to the source. A link
to this repository — <https://github.com/j-blip42/DSCSigner> — satisfies that,
and the program's own page carries it in the footer.

## No warranty

This produces legally operative signatures. It comes with no warranty of any
kind, as set out in sections 15 and 16 of the licence.

**Check your output.** Open the signed file, confirm the signature panel shows
what you expect, and confirm the stamp is where it should be. The tool
verifies that a signature was embedded; it cannot verify that you meant to
sign that document, with that certificate, in that place.
