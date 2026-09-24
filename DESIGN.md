# access-gate - Design Blueprint

Repo: `access-gate`
Companion CTF repo: `CTF_access-gate` (artifact prefix `ACT-II`)
Author: Kevin Thomas (kevin@mytechnotalent.com)

This is the build spine. It is not student-facing. The student-facing artifacts
are `README.md`, `PARTS.md`, and `paper.typ`/`paper.pdf`, exactly like the
`cold-chain-monitor` project (Act I). The companion CTF ships the canonical
`ACT-II-I.md`, `ACT-II-R.md`, `ACT-II-S.md` plus PDFs, enforced by the
`eh-project-structure` validator.

---

## Act II of the OPERATION COLD IRON story

Act I (`cold-chain-monitor`) was the silent lie: a monitor that reported a
perfect minus eighteen degrees while the store warmed. Act II is the door.

The recovered frame from Act I leads to a NorthPharma logistics annex, and
NIGHTINGALE's last ping came from inside it. FROSTLINE is wiping the site. The
only way in is the access gate. The reveal that ties the acts together: the gate
was built by the same negligent AI-assisted vendor as the monitor, so the door
inherits the same disease. Act I was "the AI wrote bad code for a sensor." Act II
is "the AI wrote bad code for a door."

The gate has two halves, and the project teaches both:

1. **Red half.** Get in using the gate's own flaws: replay a captured grant,
   forge an unlock command, flip the SRAM verdict, walk through request-to-exit.
2. **Blue half.** Seal it so it cannot be done to you: anti-replay window,
   authenticated state, locked debug port, lockout, fail-secure policy.

---

## Parity contract with Act I

`access-gate` must be structurally identical to `cold-chain-monitor`:

- Same repo layout: `README.md`, `PARTS.md`, `paper.typ`/`paper.pdf`, banner PNG,
  `LICENSE`, `.clang-format`, `.clangd`, `.github/workflows/release.yml`.
- Same crypto module set copied in: `src/chacha20.c`, `src/poly1305.c`,
  `src/crypto_aead.c`, `src/blake2b.c`, `src/argon2.c`, `src/crypto_kdf.c`,
  `src/envelope.c`, `include/field_secrets.h`, plus `scripts/field_crypto.py`.
- Same tooling: in-repo `test/harness` (no Unity), mocks, `scripts/run_tests.py`,
  `scripts/check_coverage.py`, `scripts/audit_c_standard.py`,
  `scripts/audit_python_standard.py`, `scripts/gen_banner.py`,
  `scripts/gen_packet.py`, `scripts/gateway.py`, `scripts/spoof.py`,
  `scripts/sim_edge.py`.
- Same standards: C (no blank lines in bodies, eight-line bodies, Doxygen),
  Python, and 100% line coverage.
- Same pin map, so one breadboard serves both acts.

---

## Pin map (identical to Act I, new roles)

| Pin | Act I role | Act II role |
| --- | ---------- | ---------- |
| DHT11 GP4 | cold-chain asset | vault environmental interlock |
| LCD SDA GP2 / SCL GP3 | live telemetry | access log (last badge, countdown, reason) |
| IR GP5 | second open door | badge reader and PIN keypad (primary input) |
| Servo GP14 | damper | deadbolt |
| Red GP16 | breach | DENIED |
| Yellow GP17 | warning | PENDING (authorizing) |
| Green GP18 | nominal | GRANTED |
| Button GP15 | acknowledge | request-to-exit (REX), intentionally unauthenticated |
| RYLR998 GP8/9 | telemetry uplink | authorization and audit uplink |
| Debug Probe | analysis | SRAM verdict bypass |
| Onboard GP25 | heartbeat | heartbeat |

---

## Firmware modules

Reused from Act I unchanged: the crypto stack (`chacha20`, `poly1305`,
`crypto_aead`, `blake2b`, `argon2`, `crypto_kdf`, `envelope`), `crc`, `radio`,
`display`, `status_led`, `button`, `servo`, `ir_remote`, `sensor` (DHT11).

New or rewritten for Act II:

- `src/keypad.c` / `include/keypad.h`: NEC command to PIN accumulator. Accepts
  digit commands, ENTER, and CLEAR; enforces the ready-before-consume guard and a
  bounded digit count.
- `src/auth.c` / `include/auth.h`: the authorization record and its integrity.
  Holds the anti-replay sequence window, the grant verdict, and the authenticated
  state tag. This is where the SRAM-verdict lesson lives.
- `src/monitor.c` / `include/monitor.h`: the gate state machine. IR PIN entry,
  request to the desk over LoRa, pending annunciation, grant verification,
  deadbolt control, environmental interlock, and access logging.
- `include/access_gate.h`: pin map and provisioning, mirroring
  `include/cold_chain_monitor.h`.

The wire is sealed exactly as in Act I (XChaCha20-Poly1305, Argon2id field key).
Act II adds **stateful** security on top: a monotonic sequence window so a valid
grant cannot be replayed, and a tag over the authorization record so a debugger
cannot simply set `granted = 1`.

---

## New challenges Act II introduces

- Anti-replay: a captured GRANTED frame must not work twice.
- Authorization vs authentication: proving who, then proving allowed.
- State integrity and TOCTOU: the wire is sealed, the verdict is not.
- Debug-port lockdown: the probe that fixes it also breaks it.
- Rate limiting and lockout: brute force is a real attack.
- Fail-secure vs fail-safe: a safety decision that is also a security decision.
- Designed egress: request-to-exit is deliberately unauthenticated for life
  safety, and the project discusses it rather than "fixing" it.

---

## Companion CTF: ACT-II, four deep defects

The CTF is the red half, weaponized. Fewer defects than ACT-I, each deeper:
static analysis, dynamic proof with GDB, a hardware demonstration, and an
in-place same-size patch.

| Task | Points | Defect | Fix |
| ---- | ------ | ------ | --- |
| 1 | 10 | Setup and analysis | vector table, `main`, module map |
| 2 | 25 | Replay: captured GRANTED reopens the door | restore the anti-replay window |
| 3 | 25 | Forge: the unlock tag branch is bypassed | restore tag verification |
| 4 | 25 | State: the wire is authenticated but the verdict boolean is not | restore the authenticated-state check |
| 5 | 15 | Export, verify, hardware proof, reflection | `ACT-II_fixed.bin`/`.uf2`, verifier, fail-secure proof |

Every defect is an in-place, same-size byte patch, so the shipped artifact can be
patched without moving any address, exactly like ACT-I.

---

## Naming

Project repo `access-gate`; companion `CTF_access-gate`; CTF artifact prefix
`ACT-II`. The project banner and paper carry the Act II name. The two GitHub CTFs
in the old `Embedded-Hacking` repository are unrelated and untouched.
