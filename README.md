# PQC USB Security Token on STM32F446RE — Architecture & Roadmap

Nov 1, 2026 · @MAX

## 1. Overview and threat model

The token is a USB HID device that generates and uses hybrid classical + post-quantum keys, built on a Nucleo-F446RE with an external secure element. It is a research and development platform, not a certified product: it targets a remote software attacker and a casual thief, not a funded hardware lab.

**Goals**

- Generate, store and use ML-DSA-65 and ML-KEM-768 keys, always paired with ECDSA P-256 / X25519.
- Expose operations over CTAPHID (FIDO's HID transport) using vendor commands, driven by a Python host tool.
- Host experimental algorithms behind an agility layer that can be compiled out of production builds.
- Keep key material out of reach of the USB-facing code, even if that code is compromised.

**Non-goals**

- FIDO certification, WebAuthn browser support or interoperability with commercial relying parties.
- Resistance to invasive attacks (decapping, probing) or determined voltage/EM glitching of the F446.

**Threat model**

| Attacker | Capability | Defended? | Main control |
| --- | --- | --- | --- |
| Malicious host software | Sends arbitrary USB traffic | Yes | Unprivileged parser task, MPU, strict input validation |
| Malware wanting silent use | Requests signatures without the user | Yes | Physical button on privileged GPIO, PIN |
| Thief with the device | Plugs it in, guesses PINs | Yes | PIN retry counter in the secure element, wipe on limit |
| Thief with a flash dump | Reads F446 flash via glitching | Partly | Seeds wrapped by a key that never leaves the secure element |
| Side-channel lab | Power/EM traces, fault injection | Partly | Constant-time code, verify-after-sign; no masking |
| Algorithm break | An experimental scheme is broken | Yes | Hybrid signatures and KEM combiner |

**Security target:** compromise of any single layer (USB parser, one algorithm, F446 flash contents) must not reveal a private key or allow a signature without user presence.

## 2. Hardware architecture

The F446RE does all computation; a secure element on I²C supplies entropy and guards the one key that unlocks everything else. The F446 has no TRNG and weak readout protection, so the design does not rely on either.

**MCU facts that drive the design (STM32F446RE)**

| Resource | Value | Consequence |
| --- | --- | --- |
| Core | Cortex-M4F, 180 MHz, DSP instructions | pqm4 M4 assembly runs natively |
| SRAM | 128 KB (+4 KB backup SRAM) | Stack-optimized ML-DSA; static allocation only |
| Flash | 512 KB, uneven sectors (4×16, 1×64, 3×128 KB) | Single app slot; small sectors for storage |
| RNG / HASH / CRYP | None | External TRNG; software SHA-2/SHA-3 |
| MPU | 8 regions | Privilege split replaces TrustZone |
| USB | OTG FS (PA11/PA12) | Needs external connector on Nucleo |

**USB wiring.** The Nucleo's USB port belongs to the ST-LINK. Wire a USB-A or USB-C breakout to the morpho header: PA11 → D−, PA12 → D+, GND → GND, VBUS → PA9 (optional VBUS sensing). Keep the ST-LINK cable connected for flashing, SWD debug and the virtual COM port log.

**Clocking.** USB FS needs 48 MHz within ±0.25%, which the HSI cannot guarantee. Use the 8 MHz ST-LINK MCO as HSE bypass, run SYSCLK at 168 or 180 MHz, and derive 48 MHz from PLL-Q or PLLSAI-P. Validate the tree in CubeMX before writing code.

**Secure element.** Recommended: NXP SE050 via the OM-SE050ARD Arduino shield, which plugs onto the Nucleo headers (I²C on D14/D15). Alternative: Infineon OPTIGA Trust M Shield2Go. Its roles are fixed and narrow:

1. TRNG source for the DRBG seed.
2. Holder of the device wrapping key (KW), which never leaves the chip; the SE performs AES or HMAC on request.
3. Monotonic PIN retry counter and PIN-gated access to KW.
4. Pairing secret bound to the F446 (I²C traffic protected with SCP03 or the SE's shielded connection).

**User presence.** Blue button B1 (PC13) during development; a capacitive touch pad or tactile switch on a custom board later. It is owned by the privileged crypto task.

**Bill of materials (development)**

| Item | Purpose |
| --- | --- |
| Nucleo-F446RE | Main MCU |
| NXP OM-SE050ARD (or OPTIGA Trust M Shield2Go) | TRNG, wrapping key, PIN counter |
| USB breakout + jumper wires | Device USB port |
| 8-channel logic analyzer | USB/I²C debugging |
| ChipWhisperer-Lite (Phase 7, optional) | Power analysis and glitch testing |

## 3. Firmware architecture

FreeRTOS with the Cortex-M4 MPU port splits the firmware into an unprivileged USB zone and a privileged crypto zone that share only a mailbox. This replaces TrustZone: a compromised parser can crash its own task but cannot read keys.

&#91;embedded content: firmware architecture · two MPU zones, one mailbox\]

Requests flow down the picture; every response returns through the same mailbox, and only public outputs (public keys, signatures, status codes) are ever written there.

**Software layers (bottom to top)**

1. **Platform:** CMSIS, STM32 LL drivers (preferred over HAL for size and predictability), clock and MPU setup.
2. **Kernel:** FreeRTOS 10.x/11.x `ARM_CM4_MPU` port; all tasks and queues statically allocated.
3. **Drivers:** TinyUSB (dwc2 port), I²C + SE middleware (NXP Plug&Trust or Infineon OPTIGA host library), flash storage log.
4. **Crypto core:** algorithm registry, hybrid constructions, DRBG, key derivation, wrapping — no HAL calls, so it also builds on the host.
5. **Application:** command dispatcher, PIN/session state machine, credential management.

**Tasks**

| Task | Privilege | Priority | Stack | Responsibility |
| --- | --- | --- | --- | --- |
| `usb_task` | Unprivileged | High | 4 KB | TinyUSB device task, CTAPHID reassembly, structural CBOR checks, KEEPALIVE |
| `crypto_task` | Privileged | Medium | 40 KB | Dispatch commands, wait for button, run algorithms, write responses |
| `se_task` | Privileged | Medium | 3 KB | Serialize all I²C/SE access; TRNG, HMAC with KW, PIN counter |
| `led_task` | Unprivileged | Low | 512 B | Status and WINK blinking |

**Mailbox protocol.** The USB task fills a fixed `req_t` (command, channel, lengths, payload ≤ 7.6 KB), then signals the crypto task through a FreeRTOS task notification. The crypto task copies the struct into private RAM, validates it again, executes, writes `resp_t`, and notifies back. Only one request is in flight at a time, which removes most concurrency bugs.

**State machine.** `LOCKED → (UNLOCK ok) → UNLOCKED → (idle 5 min, suspend, VBUS loss) → LOCKED`; any SE error or failed self-test enters `ERROR`, which only accepts GET\_INFO until reset.

## 4. Crypto subsystem and agility layer

Every key and operation is hybrid: one classical and one post-quantum algorithm, both required. Algorithms plug in through a descriptor table, and experimental ones live in a separate tier that production builds exclude.

**Algorithm set**

| Tier | Algorithm | Role | Source | Approx. sizes (bytes) |
| --- | --- | --- | --- | --- |
| Stable | ML-DSA-65 (FIPS 204) | Signature | pqm4 `m4fstack` | pk 1,952 · sig 3,309 |
| Stable | ML-KEM-768 (FIPS 203) | Key encapsulation | pqm4 `m4fstack` | pk 1,184 · ct 1,088 |
| Stable | ECDSA P-256 | Classical signature | micro-ecc or mbedTLS | pk 64 · sig 64 |
| Stable | X25519 | Classical key agreement | Monocypher or mbedTLS | pk 32 |
| Stable | SHA-256, SHA3/SHAKE | Hashing, KDF | Optimized C / pqm4 Keccak | — |
| Stable | AES-256-GCM | Seed wrapping (inner layer) | mbedTLS or tiny-AES with GCM | — |
| Experimental | SLH-DSA-SHA2-128s (FIPS 205) | Conservative signature | PQClean | pk 32 · sig 7,856 |
| Experimental | FN-DSA / Falcon-512 | Compact signature | pqm4 | pk 897 · sig \~666 |
| Experimental | HQC-128 | Backup KEM | PQClean / reference | Large ct |
| Experimental | Your own variants | Research | Your code | — |

SLH-DSA-128s signatures exceed CTAPHID's 7,609-byte message cap; they need the chunked vendor transfer in section 6.

**Descriptor table.** Each algorithm registers one `alg_desc_t` with: a 16-bit ID (private range for experimental), flags (`STABLE`/`EXPERIMENTAL`, `SIG`/`KEM`), key and output lengths, function pointers for `keygen_from_seed`, `sign`, `verify`, `encaps`, `decaps`, and a `kat()` self-test. Descriptors live in a dedicated linker section so the registry is assembled at link time.

**Hybrid constructions**

- Signature: `sig = ECDSA(m') || ML-DSA(m')` where `m' = SHA-256("PQTOKEN-HYB-v1" || alg_pair_id || m)`. Verifiers must check both. The domain label prevents stripping one half and reusing the other.
- KEM: `ss = SHA3-256("PQTOKEN-KEM-v1" || ss_x25519 || ss_mlkem || ct_x25519 || ct_mlkem)`, an X-Wing-style combiner binding both ciphertexts.

**Experimental tier rules**

1. Compiled only with `-DENABLE_EXPERIMENTAL`; release builds fail if any experimental descriptor is linked.
2. Never used alone: always paired with a stable algorithm of the same kind.
3. Each response carries an `experimental` flag so host tools display it.
4. Must pass KATs at boot like every other algorithm; failure disables it and logs the reason.

**Performance budget (estimates at 180 MHz, to be measured in Phase 1)**

| Operation | Target |
| --- | --- |
| ML-KEM-768 encaps/decaps | < 10 ms |
| ML-DSA-65 keygen from seed | < 20 ms |
| ML-DSA-65 sign + verify-after-sign | < 150 ms average |
| SLH-DSA-128s sign | Seconds (acceptable for experiments only) |

## 5. Key management

The token stores only short seeds, each encrypted under a key derived from the user's PIN and a secret held in the secure element. A flash dump without the PIN and the secure element yields nothing usable.

**Key hierarchy**

1. **KW (device wrapping key):** 256-bit key generated inside the SE at provisioning; never exported.
2. **KP (PIN key):** `KP = HMAC_SE(KW, PBKDF(PIN, device_salt))`. The SE computes the HMAC only while the PIN retry counter is above zero. PBKDF is PBKDF2-HMAC-SHA256 with an iteration count tuned to \~250 ms on the F446.
3. **KS (session storage key):** `KS = HKDF-SHA256(KP, "PQTOKEN-STORE-v1")`, held in RAM only while unlocked, zeroized on lock, unplug or timeout.
4. **Credential seeds:** 32 bytes for ML-DSA, 64 bytes for ML-KEM, 32 bytes for ECDSA/X25519, generated from the DRBG.

**Two credential models**

| Model | Where the seed lives | Handle returned to host | Use |
| --- | --- | --- | --- |
| Resident | Wrapped record in flash storage sectors | 16-byte random ID | Few long-lived keys (e.g. a code-signing identity) |
| Non-resident | Inside the handle itself | `version ‖ alg_pair ‖ nonce ‖ AES-GCM_KS(seeds, aad = alg_pair ‖ rp_id_hash) ‖ tag` | Unlimited keys, nothing stored |

Each use re-derives the full key pair from the seed (keygen from seed), signs, then zeroizes. This costs a keygen per operation but keeps flash usage tiny and avoids storing multi-kilobyte private keys.

**Randomness.** At boot the crypto task pulls 48 bytes from the SE TRNG to seed an HMAC-DRBG (SP 800-90A style), reseeds every 2^16 requests or on any SE error, and mixes in DWT cycle-counter jitter as a non-credited extra input. ML-DSA uses hedged (randomized) signing.

**PIN policy**

- 6 to 63 characters; set at provisioning over USB with button confirmation.
- 8 consecutive failures exhaust the SE counter: KW becomes unusable, which is a cryptographic wipe of every credential.
- Unlock state expires after 5 minutes idle or on USB suspend.

**Provisioning flow (one-time)**

1. Factory-fresh SE: establish pairing secret and SCP03 keys between F446 and SE.
2. Generate KW inside the SE; write `device_salt` to F446 flash.
3. User sets PIN; SE initializes retry counter.
4. Optional: generate a device attestation key pair (ECDSA + ML-DSA) and export its public half for your own CA.

## 6. USB protocol layer

The token enumerates as a FIDO-usage HID device and speaks CTAPHID framing, with all PQC operations carried as CTAPHID vendor commands. Standard FIDO tools ignore the vendor range, so the token coexists with real authenticators on the same host.

**USB descriptors**

- HID interface, usage page 0xF1D0, usage 0x01, 64-byte IN and OUT interrupt endpoints, 5 ms polling.
- Custom VID/PID for development (e.g. pid.codes test range); a unique serial number string per device.

**CTAPHID framing (implemented in the unprivileged USB task)**

- Init packet: 4-byte channel ID, command byte, 2-byte length, 57 data bytes.
- Continuation packets: channel ID, sequence 0–127, 59 data bytes; maximum message 7,609 bytes.
- Standard commands: INIT (allocate channel), PING, CANCEL, ERROR, KEEPALIVE (sent every 100 ms while waiting for the button), WINK (blink LED).

**Vendor commands**

| Code | Command | Request | Response |
| --- | --- | --- | --- |
| 0x40 | GET\_INFO | — | Firmware version, algorithm list with flags, limits |
| 0x41 | UNLOCK | PIN | OK or retries remaining |
| 0x42 | MAKE\_CRED | alg\_pair, rp\_id\_hash, resident flag | Handle, ECDSA pk, PQC pk |
| 0x43 | SIGN | Handle, rp\_id\_hash, 32–64 byte digest | Hybrid signature |
| 0x44 | DECAPS | Handle, X25519 + ML-KEM ciphertexts | 32-byte combined secret |
| 0x45 | LIST / DELETE | Resident credential ops | IDs / OK |
| 0x46 | XFER | Offset, chunk | Chunked transfer for outputs > 7,609 bytes |
| 0x50–0x5F | DEV\_\* | Benchmarks, KAT run, stack high-water mark | Debug builds only |

Message bodies use CBOR (TinyCBOR or a hand-written minimal encoder) with integer keys, so new fields can be added without breaking old hosts. SIGN and MAKE\_CRED always require a button press; DECAPS requires it unless the credential was created with a “no-touch” policy.

**Parser rules**

- Reject any message whose declared length, CBOR nesting depth (max 4) or field size exceeds the per-command limit before copying it.
- One outstanding request per channel; CANCEL aborts the wait for the button.
- The USB task never interprets cryptographic contents; it only checks structure and forwards a fixed-layout request struct to the mailbox.

**Host tooling.** A Python package (`pqtoken`) using `fido2`'s `CtapHidDevice` for transport: commands for `info`, `unlock`, `make-cred`, `sign`, `verify` (host-side verification with liboqs-python + `cryptography`), `bench` and `kat`. It becomes the integration test driver in section 10.

## 7. Boot chain and firmware update

A write-protected 32 KB bootloader verifies a hybrid ECDSA P-256 + LMS signature over the application before every jump; an image that fails stays unbooted and the device drops into update mode.

**Boot sequence**

1. Reset → bootloader in sectors 0–1 (write-protected via option bytes nWRP).
2. Check the application header: magic, version, length, monotonic security counter.
3. Compute SHA-256 over the image; verify ECDSA P-256 and LMS (SP 800-208, e.g. LMS-SHA256-M32-H10) signatures against public keys compiled into the bootloader. Both must pass.
4. Reject any image whose security counter is below the value stored in the SE or in a write-once flash area (rollback protection).
5. Set VTOR, MSP and jump. The application then runs its own power-on KATs before enabling USB.

**Why LMS here.** Verification is a few thousand hash calls (fast, tiny code), security rests only on SHA-256, and the stateful-signature risk sits on your offline signing machine rather than the device. Keep the LMS private key and its state counter on an air-gapped host or HSM; never in CI.

**Update mode (DFU)**

- Entered by holding the user button at plug-in, or automatically after a failed verification.
- Bootloader exposes a minimal HID vendor protocol: ERASE\_APP, WRITE\_CHUNK, FINALIZE. It does not trust the image until the full verification in step 3 succeeds on next boot.
- The bootloader never touches storage sectors 2–3, so wrapped credentials survive updates.
- During development, ST-LINK flashing stays available until RDP is raised.

**Image format**

| Offset | Field |
| --- | --- |
| 0x000 | Header: magic, header version, image version, security counter, length |
| 0x040 | ECDSA P-256 signature (64 B) |
| 0x080 | LMS signature (\~2.5 KB for H10) |
| 0xC00 | Vector table and application code |

## 8. Memory and flash map

The plan fits in 128 KB of SRAM with about 30 KB of headroom, provided all allocation is static and ML-DSA uses the stack-optimized implementation. Cortex-M4 MPU regions must be power-of-two sized and size-aligned, so the USB and mailbox regions are laid out on 8/16 KB boundaries.

**SRAM plan (initial; trim after measuring stack high-water marks in Phase 1)**

| Region | Size | Access | MPU region |
| --- | --- | --- | --- |
| USB task: stack (4 KB), CTAPHID reassembly buffer (8 KB), TinyUSB state | 16 KB | Unprivileged RW | R3 |
| Mailbox (request + response structs) | 8 KB | Unprivileged RW, privileged RW | R4 |
| Crypto task stack | 40 KB | Privileged only | Default map |
| Crypto working buffers (keys, sigs, cts, seeds) | 16 KB | Privileged only | Default map |
| SE driver task + I²C buffers | 6 KB | Privileged only | Default map |
| FreeRTOS kernel, idle/timer tasks | 6 KB | Privileged only | Default map |
| DRBG state, KS, globals (.data/.bss) | 6 KB | Privileged only | Default map |
| Headroom | \~30 KB | — | — |

Place the crypto stack in SRAM1 below a 32-byte no-access MPU guard region so overflow faults instead of silently corrupting data. The 4 KB backup SRAM can hold the lock state and a tamper flag across resets.

**Flash plan (512 KB)**

| Sectors | Address | Size | Content | Protection |
| --- | --- | --- | --- | --- |
| 0–1 | 0x0800\_0000 | 32 KB | Bootloader + public verification keys | nWRP write-protect |
| 2–3 | 0x0800\_8000 | 32 KB | Storage: device salt, resident credential records, security counter (A/B sector log) | Bootloader never writes |
| 4–7 | 0x0801\_0000 | 448 KB | Application image with header and signatures | Verified each boot |

**Storage format.** An append-only log of fixed 256-byte records (type, length, sequence, payload, CRC) alternating between sectors 2 and 3. When one fills, live records are copied to the other and the old sector is erased. Every payload holding key material is AES-GCM wrapped under KS.

**Code size estimate.** FreeRTOS + HAL/LL + TinyUSB ≈ 40 KB; ML-DSA + ML-KEM + Keccak ≈ 40–60 KB; ECC + AES + SHA-256 + DRBG ≈ 25 KB; SE middleware ≈ 30–60 KB; CBOR + app logic ≈ 20 KB. Total ≈ 160–200 KB, leaving ample room for experimental algorithms.

## 9. Security hardening

Hardening targets timing leaks, single-fault attacks and residual secrets in memory; full power-analysis resistance (masking) is out of scope for this hardware.

**Timing and side channels**

- Use only constant-time implementations (pqm4, Monocypher/micro-ecc in constant-time mode); no secret-dependent branches, table lookups or early returns.
- Disable the flash ART accelerator's data cache during secret-dependent code paths, or verify timing with it enabled, since cache hits can leak access patterns.
- Avoid Falcon outside the experimental tier: its floating-point sampler is hard to make constant-time on an M4F.
- Constant-time comparison for PINs, tags and handles.

**Fault injection**

- Verify every signature on-device before returning it (catches faults in ML-DSA and ECDSA that could leak key bits).
- Duplicate critical decisions: check PIN result, button state and boot verification twice with complementary encodings (e.g. 0x5AA5 vs 0xA55A), never a single boolean.
- Add random delays (from the DRBG) before security-critical branches to desynchronize glitch timing.
- Enable the brown-out reset at the highest threshold (BOR level 3).

**Memory hygiene**

- Zeroize seeds, expanded keys and intermediate buffers with a non-elidable `secure_zero()` after each operation and on every error path.
- Paint and wipe the crypto stack after each request.
- Clear KS and unlock state on USB suspend, unplug detection (VBUS loss) and idle timeout.

**Option bytes and lifecycle**

| Stage | RDP | nWRP | Debug |
| --- | --- | --- | --- |
| Development | Level 0 | Off | SWD open |
| Test devices | Level 1 | Sectors 0–1 | SWD can attach, flash read blocked |
| Release | Level 2 (irreversible) | Sectors 0–1 | SWD permanently disabled |

RDP on the F4 family has been bypassed by glitching, which is why secrets are protected by the secure element rather than by RDP alone. Treat RDP as raising cost, not as a guarantee.

**Compiler and code hygiene.** `-fstack-protector-strong`, `-Wall -Wextra -Werror`, `-fno-common`; MISRA-inspired rules for the parser; static analysis with cppcheck or clang-tidy in CI.

## 10. Testing and verification

Most logic is built twice: once for the host (fast tests, fuzzing, timing analysis) and once for the target. A hardware abstraction layer keeps crypto, CBOR and CTAPHID code free of HAL calls so the same sources compile on both.

| Layer | Method | Tooling | When |
| --- | --- | --- | --- |
| Algorithms | NIST KAT and ACVP vectors, on host and on target at boot | Unity test runner, vector files in flash | Every commit / every boot |
| Hybrid constructions | Cross-verify token output with an independent host implementation | liboqs-python, `cryptography` | Every commit |
| CTAPHID + CBOR parser | Coverage-guided fuzzing of the host build | libFuzzer + AddressSanitizer + UBSan | Nightly, ≥1 h |
| Constant time | Statistical timing tests on host; cycle-count spread on target | dudect, DWT cycle counter | Per algorithm change |
| Isolation | Deliberate out-of-bounds access from the USB task must MemManage-fault | On-target test build | Every release |
| Integration | Python host suite: unlock, make-cred, sign, verify, decaps, wrong PIN, cancel, unplug mid-op | pytest + `pqtoken` | Every release |
| Storage robustness | Power-cut during writes (relay on VBUS), log recovery | Scripted relay + pytest | Phase 5 onward |
| Side channel / faults | Power traces (TVLA), clock and voltage glitch campaigns | ChipWhisperer-Lite | Phase 7 |

**Continuous integration.** GitHub Actions or GitLab CI: build bootloader and app for target, run host unit tests and a short fuzz smoke run, fail on any experimental descriptor in release builds, and archive map files to track RAM/flash growth.

**Hardware-in-the-loop (optional).** A Raspberry Pi with the Nucleo attached runs the pytest suite on each merge, flashing via ST-LINK and reading the virtual COM port log.

## 11. Implementation roadmap

Eight phases take the board from blinky to a hardened research token in roughly 15–17 weeks of focused work; each phase ends at a gate that must pass before the next starts. Phases 1 and 2 can run in parallel if two people share the work.

&#91;embedded content: implementation roadmap · 8 phases, 7 gates\]

The order front-loads the risky, portable parts (crypto, USB) and leaves platform hardening until the functionality is proven.

### Phase 0 — Toolchain and board bring-up (1 week)

- [ ] Install STM32CubeIDE or arm-none-eabi-gcc + CMake + OpenOCD; set up the Git repo and CI skeleton.
- [ ] Configure clocks in CubeMX: HSE bypass 8 MHz, SYSCLK 180 MHz, 48 MHz USB clock.
- [ ] UART logging over the ST-LINK virtual COM port; `printf` retarget.
- [ ] Enable the DWT cycle counter; write a `bench()` helper.
- [ ] Wire the USB breakout to PA11/PA12/GND/PA9.

Deliverable: repository template that builds, flashes and logs.

### Phase 1 — PQC algorithms on target (2–3 weeks)

- [ ] Import pqm4 `m4fstack` and `m4f` variants of ML-KEM-768 and ML-DSA-65, plus Keccak.
- [ ] Add ECDSA P-256 and X25519 (constant-time libraries).
- [ ] Port NIST KAT vectors; run them on host and target.
- [ ] Measure cycles and stack high-water marks for each operation; record them in this doc.
- [ ] Define `alg_desc_t` and the registry linker section.

Deliverable: `crypto-core` library with KATs passing on both host and target, plus a benchmark table.

### Phase 2 — USB HID and CTAPHID (2–3 weeks)

- [ ] Integrate TinyUSB; enumerate as a FIDO-usage HID device with a custom VID/PID.
- [ ] Implement CTAPHID INIT, PING, CANCEL, ERROR, KEEPALIVE, WINK and multi-packet reassembly.
- [ ] Build the host-side parser target and a libFuzzer harness.
- [ ] Start the `pqtoken` Python package with `fido2` transport.

Deliverable: host can open a channel and round-trip 7,609-byte PINGs.

### Phase 3 — Commands and hybrid credentials (2 weeks)

- [ ] CBOR request/response encoding with integer keys and strict limits.
- [ ] GET\_INFO, MAKE\_CRED, SIGN, DECAPS vendor commands; button press required.
- [ ] Hybrid signature and KEM combiner as specified in section 4.
- [ ] Host-side verification with liboqs-python and `cryptography`.
- [ ] Temporary key storage in RAM only (no persistence yet).

Deliverable: Milestone A — a working hybrid PQC token demo.

### Phase 4 — Secure element and key storage (3 weeks)

- [ ] One-week spike: SE050 vs OPTIGA Trust M middleware size and I²C latency; decide.
- [ ] SE bring-up with SCP03 pairing; TRNG feeding HMAC-DRBG.
- [ ] KW generation, PIN retry counter, KP/KS derivation, UNLOCK command.
- [ ] Non-resident handles (AES-GCM wrapped seeds) and resident credential storage log.
- [ ] Power-cut test for the storage log.

Deliverable: credentials survive reboot; a raw flash dump contains no usable key material.

### Phase 5 — MPU isolation (2 weeks)

- [ ] Move to the FreeRTOS `ARM_CM4_MPU` port; define regions per section 8.
- [ ] Split `usb_task` (unprivileged) and `crypto_task`/`se_task` (privileged); mailbox with task notifications.
- [ ] Stack guard regions; MemManage and HardFault handlers that log and lock.
- [ ] Negative tests: USB task reads key buffer, writes outside its region.

Deliverable: isolation test suite proving the USB zone cannot reach secrets.

### Phase 6 — Boot chain and hardening (2–3 weeks)

- [ ] Bootloader with hybrid ECDSA + LMS verification and rollback counter.
- [ ] Offline signing tool and image format; DFU vendor protocol.
- [ ] Zeroization pass, verify-after-sign, duplicated checks, random delays, BOR level 3.
- [ ] nWRP on sectors 0–1 and RDP level 1 on test devices.
- [ ] Full pytest integration suite in CI.

Deliverable: Milestone B — a hardened development token.

### Phase 7 — Experimental algorithms and evaluation (ongoing)

- [ ] Add SLH-DSA-128s with chunked XFER transport; Falcon-512 and HQC as experiments.
- [ ] Enforce hybrid-only use and the release-build check.
- [ ] ChipWhisperer power traces (TVLA) and glitch campaigns against PIN check and signing.
- [ ] Write up results; decide whether a custom PCB stays on F446 + SE or moves to STM32U5.

## 12. Risks, limitations and open questions

The largest risks are physical attacks on the F4, the immaturity of PQC standards in FIDO, and secure-element middleware size. Each has a fallback.

| Risk | Impact | Mitigation / fallback |
| --- | --- | --- |
| F446 RDP bypass by glitching | Flash contents readable | Secrets wrapped by SE-held key; move to STM32U5/H5 for a product |
| No masking for ML-DSA/ML-KEM | Key recovery with many power traces | Limit signing rate, verify-after-sign; treat as research device |
| SE middleware too large or I²C too slow | Flash/latency budget exceeded | Use OPTIGA Trust M (smaller host library) or minimal custom APDU layer |
| RAM overruns with ML-DSA | Hard faults | Stack-optimized variant, guard region, measured high-water marks |
| PQC not yet in CTAP/WebAuthn | No browser interoperability | Vendor commands now; add COSE IDs when IETF drafts settle |
| Experimental algorithm broken | Loss of PQ security for its users | Hybrid always; tier compiled out of releases |
| LMS signing state mishandled | Firmware signing key compromise | Offline signer, state backups with strict monotonic counter |
| USB stack bugs | Parser compromise | Unprivileged task, fuzzing, small attack surface |

**Open questions**

- [ ] SE050 or OPTIGA Trust M: decide after a one-week spike on middleware size and I²C latency.
- [ ] Which experimental algorithms are in scope for the first research milestone?
- [ ] Is FIDO2/WebAuthn compatibility (classical-only credentials) wanted later, or vendor-only forever?
- [ ] Target for a custom PCB: stay on F446 with SE, or migrate to STM32U5?
