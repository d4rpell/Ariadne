# Visual walkthrough assets

Two small, deterministic animations of the offline tool, plus their static
alternatives. They illustrate the **shipped** behaviour over **synthetic**
fixtures. They are presentation only: an animation is **not** an integration
proof (see [ADR-0021](../adr/ADR-0021-lab-and-integration-validation.md)).

| File | What it is |
|---|---|
| `ariadne-flow.png` | Static sheet of the flow walkthrough (shown in the README) |
| `ariadne-flow.gif` | Animated version of the same flow (voluntary open only) |
| `ariadne-serve.png` | Static sheet of the `serve` dashboard walkthrough (shown in the README) |
| `ariadne-serve.gif` | Animated version of the same dashboard walkthrough (voluntary open only) |

The README embeds the **static PNGs**, never the GIFs, so nothing animates on
its own. The GIFs are offered as links for readers who choose to open them.

## Text transcription — flow (`ariadne-flow.gif` / `.png`)

One walkthrough, one subject. Every value below is real output of the built
binary over the synthetic fixtures named in the manifest. The footer of every
frame reads "Ariadne | MVP complete | offline | synthetic data".

1. **Title.** "Ariadne — finding → evidence → decision" / "offline, synthetic
   fixtures, human risk decision".
2. **Input.** A `prisma-v1` CSV (`fixture.csv`, 2 rows) plus explicit operator
   bindings: subject `payments-api`, container `api` (regular), vulnerability
   `CVE-2026-1001`.
3. **`import`.** CSV + bindings become a canonical hashable bundle;
   `bundle_hash = sha256:4ed5b0ce9c…f48b16`, rows `2 accepted / 0 rejected`.
4. **`evaluate`.** Declarative rules run over **that** bundle;
   `result_fingerprint = sha256:ff12bba791…c0e549`. Product status lands
   `under_investigation` — insufficient evidence stays unknown, **never**
   `not_affected`.
5. **`report`.** Deterministic JSON/HTML presentation; `risk_decision: null`
   (the human layer is recorded separately), `exploitability: not_assessed`.
   The report states it "renders the computed result; adds no conclusion", and
   the tool is a completed, offline, pre-release MVP.
6. **`book` + `append`.** An append-only human decision record is started and
   one decision is declared: `accepted`, `records = 1`,
   `head_hash = sha256:75c1ca1f00…8a0ddc`.
7. **`append` + `diff`.** A second decision is declared (`deferred`,
   `records = 2`, `head_hash = sha256:1dcf7de186…0dfeda`) and the validity diff
   over two declared instants reports `{subjects: 1, changed: 1}`.
8. **Close.** "risk_decision is human; hashes prove integrity, not
   authenticity" — a synthetic walkthrough, not an integration proof.

## Text transcription — dashboard (`ariadne-serve.gif` / `.png`)

`ariadne serve` reads the **same** book produced above (`b2.json`) and opens a
read-only loopback dashboard. No value below is invented; it is the rendered
page.

1. **Dashboard header.** "Ariadne governance dashboard" with the limits
   banner: "read-only projection of one human decision record; not a risk
   acceptance, not an approval, not a security statement; not a source of
   truth."
2. **Book observation.** Records `2`; As of `2026-11-01T00:00:00Z`; Book head
   hash `sha256:1dcf7de186…0dfeda`.
3. **Derived summary.** `standing`: effective `2`, pending `0`, expired `0`,
   superseded `0`. `risk_decision`: accepted `1`, deferred `1`, rejected `0`.
   Counts are derived from the entries, including expired and superseded
   declarations.
4. **Decision records.** Two rows for subject `11111111-2222-3333-4444-555555555555`,
   container `api`, `CVE-2026-1001`: sequence 1 `accepted` (effective), sequence
   2 `deferred` (effective); both `anomalies: none`.
5. **`/decision/1` — Declaration + Scope.** Declaration: `hash sha256:75c1ca1f00…`,
   `risk_decision accepted`, owner `platform-owner`, approver `security-approver`,
   rationale "synthetic acceptance for the animated walkthrough", decided
   `2026-10-07T10:00:00Z`, expires `2027-04-07T00:00:00Z`. Scope: `bundle_hash
   sha256:4ed5b0ce9c…f48b16`, subject/container/vulnerability as above.
6. **`/decision/1` — Controls + validity.** Controls: `scanner-feed-pinned`,
   `weekly-revalidation`. Derived validity view: `standing effective`,
   `superseded_by null`, `anomalies none`.

## Reproducing the walkthrough

The walkthrough is reproducible with the offline CLI and the fixtures in this
repository. The complete recipe below was verified literally from this
repository root in the recorded environment; it is the source of every receipt
cited above. `serve` (last line) needs no external network — it binds
`127.0.0.1` and is captured with a local HTTP client — and blocks until
interrupted.

```bash
go build -o ariadne.exe ./cmd/ariadne
OUT=ax08-demo
mkdir -p "$OUT"
BIN=./ariadne.exe
PACK=fixtures/F09-unmapped-redhat-package/0.2/input/pack.json

# 1) import: synthetic CSV + bindings -> canonical hashable bundle
$BIN import \
  --findings cmd/ariadne/testdata/import/fixture.csv \
  --bindings cmd/ariadne/testdata/import/bindings.json \
  --observed-at 2026-10-07T09:00:00Z \
  --out-envelope "$OUT/bundle.json" \
  --out-projection "$OUT/bundle.hash-input.json" \
  --out-digest "$OUT/bundle.sha256"
BH="$(cat "$OUT/bundle.sha256")"   # sha256:4ed5b0ce9cb9171f…48b16

# 2) the evaluation context of the imported subject (target = the bindings'
#    subject/container/vulnerability; admission + domain policies from the F09
#    fixture, with the fixture's omitted nullable members materialized as null)
cat > "$OUT/context.json" <<'JSON'
{"admission":{"evaluated_at":"2026-10-01T12:00:00Z","expected_pack_hash":"sha256:492d5d023c5180e1cd2073b2f2abf25ba944134c6b9c343e559005cd68a276d1","expected_pack_id":"pack.fixtures","minimum_version":1,"previous":null},"domain":{"maximum_evidence_age_seconds":2592000,"source_pins":[{"advisory_id":null,"advisory_revision":null,"role":"artifact","source":"inspection.json","source_hash":"sha256:e0b1ab4388a19d75579b6249673a49f1ce3240d1126fba8f2fe1dff59bd8592f"}]},"target":{"container_class":"regular","container_name":"api","locator":"items[0].status.containerStatuses[0].imageID","observed_at":"2026-10-07T09:00:00Z","source":"sanitized-pods.json","source_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","subject_uid":"11111111-2222-3333-4444-555555555555","vulnerability_id":"CVE-2026-1001"}}
JSON

# 3) evaluate the imported bundle, then render a report
$BIN evaluate --bundle "$OUT/bundle.json" --bundle-hash "$BH" \
  --pack "$PACK" --context "$OUT/context.json"
$BIN report --bundle "$OUT/bundle.json" --bundle-hash "$BH" \
  --pack "$PACK" --context "$OUT/context.json" --format html --out "$OUT/report.html"

# 4) two human decisions on the same subject
$BIN book --out "$OUT/b0.json"
$BIN append --casebook "$OUT/b0.json" --decision accepted \
  --owner platform-owner --approver security-approver \
  --rationale "synthetic acceptance for the animated walkthrough" \
  --bundle-hash "$BH" --subject-uid 11111111-2222-3333-4444-555555555555 \
  --container-name api --container-class regular --vulnerability-id CVE-2026-1001 \
  --decided-at 2026-10-07T10:00:00Z --expires-at 2027-04-07T00:00:00Z \
  --controls "scanner-feed-pinned,weekly-revalidation" --out "$OUT/b1.json"
$BIN append --casebook "$OUT/b1.json" --decision deferred \
  --owner platform-owner --approver security-approver \
  --rationale "synthetic deferral pending a corrected component mapping" \
  --bundle-hash "$BH" --subject-uid 11111111-2222-3333-4444-555555555555 \
  --container-name api --container-class regular --vulnerability-id CVE-2026-1001 \
  --decided-at 2026-10-20T10:00:00Z --out "$OUT/b2.json"

# 5) validity diff over two declared instants
$BIN diff --casebook "$OUT/b2.json" --since 2026-10-01T00:00:00Z \
  --as-of 2026-11-01T00:00:00Z --out "$OUT/diff.json"

# 6) read-only dashboard over the same book (loopback only; blocks until stopped)
$BIN serve --casebook "$OUT/b2.json" --as-of 2026-11-01T00:00:00Z --port 8799
```

Expected receipts (stdout):

- `import` → `{"bundle_hash":"sha256:4ed5b0ce…48b16","rows_total":2,"rows_accepted":2,"rows_rejected":0,"omissions":0,"scope_collisions":0}`
- `evaluate` → `{"bundle_hash":"sha256:4ed5b0ce…48b16","result_fingerprint":"sha256:ff12bba791…c0e549"}`
- `book` → `{"records":0}`
- `append` (accepted) → `{"records":1,"head_hash":"sha256:75c1ca1f00…8a0ddc"}`
- `append` (deferred) → `{"records":2,"head_hash":"sha256:1dcf7de186…0dfeda"}`
- `diff` → `{"subjects":1,"changed":1}`

The **exact image/GIF bytes** additionally require the generator toolchain
(Pillow + Playwright) and the recorded environment; regenerating the images byte
for byte is **reserved to the maintainer** in this scope. Nothing here claims
cross-platform byte-for-byte equivalence; the recorded environment is
windows/amd64.

## Determinism manifest

Recorded environment (2026-10-08), base code revision `350f49aa193545b92baac5c3e29e45a15ba8c56f`. The **flow** GIF/PNG were regenerated for [ADR-0039](../adr/ADR-0039-state-label-and-distribution-scope.md) (state label and withdrawal of the distribution clause); the CLI receipts are unchanged, so only the printed presentation text differs. The **dashboard** GIF/PNG are unchanged (they show neither the label nor the clause):

| Component | Value |
|---|---|
| OS | Windows 10.0.22621 (amd64) |
| Go / binary | go1.23.4 windows/amd64, `go build ./cmd/ariadne` |
| Python / Pillow / FreeType | 3.12.10 / 12.3.0 / 2.14.3 |
| Node / Playwright / Chromium | 24.13.0 / 1.64.0 / build 1248 |
| Embedded flow font | Aileron Regular, bundled in Pillow 12.3.0 (`ImageFont.load_default(size=N)`, base64; CC0 1.0 / No Rights Reserved — dotcolon.net/fonts/aileron, consulted 2026-10-08). The TTF is not redistributed; only rendered images are. Embedded bytes (5143 B) SHA-256 `5e85438582f0e790b6b115d1afd66fa439d9fc45875af5cc760af7034d67187a`; the base64 literal in `ImageFont.py` SHA-256 `1ca26a4ba182d92f95bfa2de5e98971b68976b9fcc18b2232663fcdb8dd8b0c8`. |
| Dashboard font (effective) | `system-ui, sans-serif` resolves to **Segoe UI** on the recorded OS. Chromium's platform-font probe (CDP `CSS.getPlatformFontsForNode`) reports families actually rendered: `Segoe UI` (SegoeUI, SegoeUI-Bold) and `Segoe UI Semibold` (SegoeUI-Semibold) — no fallback family observed. System TTF SHA-256: `segoeui.ttf 74f2b3d0c20cf7380eb121a09fd7cdfdc1ccdd12a00db83caec0feb48b4db9f7`, `segoeuib.ttf d105038ae445a7ab3e7c037eae9c6a436f71f603136f353e8338cfca40e6ca18`, `seguisb.ttf b381730d47408ced8f104b62c9042a6abbbd08501a37f14b76858760a6cf176c`. |

Generators (private; not distributed — hashes recorded so the recipe can be
reconstructed):

| Generator | SHA-256 |
|---|---|
| `run_chain.sh` (CLI chain) | `843168f1c4e544c376358c128b4e7cff8446e21dacfda6e7b9502dcb07cdee75` |
| `gen_flow.py` (flow frames + GIF + sheet) | `4d3b5c6dcfd60cb3b7ab7a60d7edb86809c899bd2075de3b704469f3da146d9c` |
| `gen_serve.py` (dashboard frames + GIF + sheet) | `4c912f69552eb1c03f3987dc00384cc88f7d9f1e00db98dc3c17f761c63c4fc9` |
| `gen/sections.mjs` (captures) | `10dbc687ad5a410f1dd7dbf46198aeccf3ddf4ad1c83e7e7b2e80b9726f4125c` |
| `gen/offsets.mjs` (section geometry) | `cdfa141676c9bb5f58d189b05f3c54f2a6abe7fab5f801d1602cd3ce4252c4bf` |

Flow GIF (Pillow): size `800×450`; explicit 15-colour RGB palette, in order —
`#0b0e14 #d7dae0 #8b93a1 #5ac8a0 #e6b45a #e06c75 #6eaae6 #181e2a #283242 #aab0bc #78808e #c8d2dc #3c4658 #96c8be #c8a078` — dither `NONE`; per-frame
duration `700 ms`; `loop=0`; `optimize=False`; `disposal=2`. Frames: 8 (title,
input, import, evaluate, report, append, append+diff, close); the static sheet is
a 2×4 montage of the same 8 frames. Font sizes used: title 64, section 34,
subtitle 28, label/value 20, note 15.

Dashboard GIF (Playwright capture + Pillow encode): viewport `1280×800`,
`deviceScaleFactor=1`, `colorScheme=light`, `reducedMotion=reduce`,
`locale=en-US`, `timezoneId=UTC`, `waitUntil=networkidle`, `animations=disabled`,
flags `--force-color-profile=srgb --font-render-hinting=none`. Capture: full page
at natural height (`/` 1074 px; `/decision/1` 1299 px), then six section crops at
their measured offsets — `/`: header 0–135, Book observation 155–318, Derived
summary 346–663, Decision records 691–919; `/decision/1`: header+Declaration+Scope
0–926, Controls+validity 954–end. GIF size `1280×800`; 16-colour palette, in
order — `#ffffff #18212b #4b5563 #107a57 #f5f7f9 #e5e7eb #d1d5db #9ca3af #111827 #dcfce7 #105a46 #78350f #fef3c7 #c8cdd4 #8c929c #fafafa` — dither
`NONE`; per-frame duration `1000 ms`; `loop=0`; `optimize=False`; `disposal=2`.
Static sheet: 2×3 montage of the same 6 frames.

Viewport note: the approved contract set `960×600`; the implementation uses
`1280×800`. The dashboard's Decision records table is 1200–1232 px wide and was
clipped at 960 px, so the frame width was raised to keep every value legible. The
adjustment is registered here, and all six dashboard frames were reviewed for
legibility and coverage.

Inputs (SHA-256):

| Input | SHA-256 |
|---|---|
| `cmd/ariadne/testdata/import/fixture.csv` | `3a21dc224a7742470122fee31742f3f23e1113b9e232b8fa0ff39218bba665d7` |
| `cmd/ariadne/testdata/import/bindings.json` | `35d76e5972be448f3885b74e7ced987b1866f02e3b5842722d8074454ad60960` |
| `fixtures/F09-unmapped-redhat-package/0.2/input/pack.json` | `492d5d023c5180e1cd2073b2f2abf25ba944134c6b9c343e559005cd68a276d1` |
| `fixtures/F09-unmapped-redhat-package/0.2/input/admission-context.json` | `826fdc8d2b4c6ffd125a797b65e55a3f63a3cd331654131c1d2979c15c3db7e0` |
| `fixtures/F09-unmapped-redhat-package/0.2/input/domain-context.json` | `26f24e17d86d47738ac00711f117ed06704c6ca6da85ddf4b88d5b897bcd9951` |

Published artifacts (SHA-256):

| Artifact | Bytes | SHA-256 |
|---|---|---|
| `ariadne-flow.gif` | 65929 | `affa0f642dd21feb58b01e4620c45d2b1e348ca6e4f63f2f1787ae9d6b5c8d20` |
| `ariadne-flow.png` | 116856 | `a364e52df2f9256486b78c769cc8ec283770f1c06b198402411db7551d7e8f1b` |
| `ariadne-serve.gif` | 130304 | `4e06f4a019e628fa21ecacd6222e9aaa57e95727770c7d7b3210812ceecda427` |
| `ariadne-serve.png` | 187478 | `638c16ff2c9622b1e996ada7494f6fe71d043a073b43d17b1cf8888e04e534fe` |

Determinism check: two full runs from empty working directories (build, whole
CLI chain, captures, PNGs and GIFs) produced byte-identical artifacts and
identical receipts.

## Limits

- Presentation, not an integration proof (ADR-0021). No cluster, no scanner
  account and **no external network** are involved; the dashboard is served over
  loopback only. Every identifier, digest, timestamp and package is synthetic.
- The GIFs are derived artifacts; the PNGs and this transcription carry the
  accessible load and the transcriptions are complete without the animations.
- Byte-for-byte reproducibility of the images is guaranteed only in the recorded
  environment (windows/amd64); the recorded dashboard font is `system-ui, sans-serif`.
- No external WCAG conformance is claimed.
- The tool is a completed, offline, pre-release MVP; no release or external distribution is provided.
