# custom-os / v2 — real UI / behaviour changes

**Goal:** ship an actual modification (branding, an extra page, a tweak to the web UI
behaviour) and understand where the limits of the "fixed-slot" repack are.

**Status:** ☐ not started   ☐ built   ☐ tested   ☐ works   ☐ failed

Ideas, smallest to largest:

| # | idea | where | risk |
|---|---|---|---|
| 1 | rebrand titles / logo | `Index.htm`, `top.htm`, `*.jpg` | low (images may shrink, never grow) |
| 2 | add a link to a new page | `menu.js` + a new `*.htm` | medium — a new file needs a free record |
| 3 | tweak the localisation strings | `str_menu.js`, `str_err.js`, `char_set.js` | low, files are large (easy to fit) |
| 4 | auto-fill or hide fields on a config page | `*Rpm.htm` | low, changes are tiny |

Note the **slot rule**: `repack` can only shrink a stream. If a change makes a file's compressed
form larger than the original slot, either

* shrink the change (or split it into a file that has spare room), or
* grow the filesystem store — which means rebuilding the record table *and* updating image #2's
  header field `+0x60` (store size) plus the total length fields. That layout rebuild is the next
  tool to write, and it belongs to v3.

## Build log

| date | files changed | result | md5 of the image |
|---|---|---|---|
| | | | |
