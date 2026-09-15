#!/usr/bin/env bash
#
# setup_and_push.sh — materialise the W-TVC Protocol repository.
#
# Writes every source file, initialises a git repository, and makes the initial
# commit. Generated directly from a working tree in which the full test suite
# passes, so the files written here are the files that were verified.
#
# Usage:
#   ./setup_and_push.sh [target-directory]      # default: ./w-tvc-protocol
#   ./setup_and_push.sh .                       # use the current directory

set -euo pipefail

TARGET="${1:-w-tvc-protocol}"

if [ -e "$TARGET/.git" ]; then
  echo "error: $TARGET already contains a git repository." >&2
  echo "       Refusing to overwrite it. Remove it or choose another target." >&2
  exit 1
fi

mkdir -p "$TARGET"
cd "$TARGET"

echo "==> Writing source tree into $(pwd)"
mkdir -p tvc-core/src tvc-cli/src nostr-bridge/src

echo "  README.md"
cat > 'README.md' <<'__W_TVC_FILE_0__'
# W-TVC Protocol

**Weight Threshold Verification Ceremony** — prove which AI model served an inference, without trusting the provider, a hardware enclave, or any party on the runtime path.

Built for **Bitshala BOSS Battle** · Tracks: **Machine Money** × **Freedom Stack**

```
Ship code. Beat the boss.
```

---

## The problem

An autonomous agent asks a remote model to authorise a payment. The model answers. The payment goes through.

Which model actually answered?

Nobody knows. The provider advertises a flagship model, routes the request to a cheaper distillation, and bills for the flagship. This is **token downgrading**, and it is invisible by construction: the output is plausible, the latency is better, and the only entity who could tell you is the entity with the incentive not to. As soon as software transacts on its own behalf, this stops being a billing dispute and becomes a payment-authorisation vulnerability — the agent's judgement is only as good as the model behind it, and the agent cannot check which model that was.

The usual answer is a **hardware TEE**: run the model in an enclave and have the silicon attest to the binary. That trades a trusted provider for a trusted silicon vendor. It has not gone well — SGX, SEV, and friends have a long CVE history — and it does not work at all for a model you rent rather than own. It also puts an attestation service on the runtime path of every single inference.

## The approach

Move the trust from silicon to arithmetic, and pay the expensive cost exactly once.

A Groth16 trusted setup depends only on the **shape** of the constraint system, never on any witness. The shape is fixed by the model architecture. So one ceremony per model version produces one verifying key that covers every inference that version will ever serve. Freeze it into 32 bytes, sign it, publish it to Nostr, and every downstream wallet can verify locally forever — no authority to ask, no service to call, no enclave to trust.

| | Phase 1 — Genesis | Phase 2 — Runtime |
|---|---|---|
| **Frequency** | Once per model version | Every inference |
| **Cost** | 78 ms (this circuit) | 128-byte proof, local check |
| **Trust** | Ceremony participants + public transcript | None |
| **Output** | 32-byte digest on Nostr relays | ACCEPT / REJECT |

---

## Phase 1 — Genesis Setup Ceremony

```
  bitshala            ┌──────────────────────────────────────┐
  entropy ───────────►│                                      │
                      │   hash-chained transcript            │
  acme-labs           │   (append-only, publicly auditable)  │──► ceremony seed
  entropy ───────────►│   tagged SHA-256, length-prefixed    │         │
                      │                                      │         │
  independent         │                                      │         │
  auditor  ──────────►└──────────────────────────────────────┘         │
  entropy                                                              │
                                                                       ▼
                                                         ┌──────────────────────────┐
                                                         │  Groth16 circuit setup   │
                                                         │  (BN254, arkworks)       │
                                                         └────────────┬─────────────┘
                                                                      │
                                          ┌───────────────────────────┴──────────┐
                                          ▼                                      ▼
                                  proving key (1840 B)                 verifying key (360 B)
                                  → to the AI provider                           │
                                                                    tagged SHA-256 domain hash
                                                                                 │
      ┌───────────────────────┐                                                  ▼
      │  TOXIC WASTE          │                                    ╔═════════════════════════╗
      │  ceremony seed +      │─── volatile overwrite ──► GONE     ║  32-byte vk digest      ║
      │  every contribution   │    (zeroize, full capacity)        ║  the permanent anchor   ║
      └───────────────────────┘             │                      ╚════════════╤════════════╝
                                            ▼                                   │
                                   burn attestation ────────────────────────────┤
                                   (publishable evidence)                       │
                                                                 BIP-340 Schnorr sign (secp256k1)
                                                                                │
                                                                                ▼
                                                            ┌───────────────────────────────┐
                                                            │  Nostr event, kind 30200      │
                                                            │  d = <model_id>:<version>     │
                                                            └───────────────┬───────────────┘
                                                                            │
                                      ┌──────────────┬──────────────┬───────┴────────┐
                                      ▼              ▼              ▼                ▼
                                relay.damus.io    nos.lol    relay.primal.net   nostr.mom
```

The entropy that could forge proofs is destroyed before the ceremony process exits. What survives is 32 bytes, a signature, and a transcript anyone can re-check.

## Phase 2 — Runtime Verification

```
   user ──► SPOT Wallet ──► "authorise ₹4,200 UPI payment"
                 │
                 │  ① resolve the commitment  (kind 30200, #d = model:version, author pinned)
                 ▼
        ┌─────────────────┐
        │  Nostr relays   │──────► 32-byte vk digest  +  BIP-340 signature
        └─────────────────┘        (any relay will do — the signature is the trust, not the host)
                 │
                 │  ② request the inference
                 ▼
        ┌─────────────────┐
        │  AI provider    │──────► output  +  Groth16 proof (128 B)  +  verifying key (360 B)
        └─────────────────┘
                 │
                 │  ③ verify locally — no network, no authority, no enclave
                 ▼
   ╔═══════════════════════════════════════════════════════════════════════╗
   ║                                                                       ║
   ║   a.  digest = tagged_hash(runtime verifying key)                     ║
   ║                                                                       ║
   ║       digest == digest from relay ?                                   ║
   ║              │                                                        ║
   ║              ├── NO ──► ✗ REJECT — model substitution                 ║
   ║              │          the proof may be perfectly valid, but it      ║
   ║              │          was made against a DIFFERENT circuit          ║
   ║              ▼ YES                                                    ║
   ║                                                                       ║
   ║   b.  Groth16 pairing check (proof, key, public inputs)               ║
   ║              │                                                        ║
   ║              ├── NO ──► ✗ REJECT — invalid execution                  ║
   ║              ▼ YES                                                    ║
   ║                                                                       ║
   ║          ✓ ACCEPT — the committed model produced this output          ║
   ║                                                                       ║
   ╚═══════════════════════════════════════════════════════════════════════╝
```

**The order is the security argument.** A downgrading provider can produce proofs that are *internally valid* — correct proofs about the wrong circuit. Checking the commitment **before** the proof, and reporting the two failures as distinct outcomes, is what turns "verification failed" into "you swapped the model". `tvc demo` demonstrates exactly this attack being caught.

---

## Quick start

```bash
git clone <your-remote> && cd w-tvc-protocol

cargo test --workspace          # 41 Rust tests
cargo build --release
./target/release/tvc demo       # full lifecycle + a caught forgery
```

The demo runs a real ceremony, a real proof, and a real rejection in about a second:

```
== Phase 1: Genesis Setup Ceremony ==
  committed digest  61bdcdf664b14d77555299d35c2492a76db019784912c28b1473c0cde554fa31
  transcript chain  verified
  entropy burned    128 bytes

== Phase 2: honest runtime inference ==
  wallet verdict    ACCEPTED

== Phase 2 under attack: silent model downgrade ==
  rogue proof is internally valid against its own key: true
  wallet verdict    REJECTED
    committed       61bdcdf664b14d77555299d35c2492a76db019784912c28b1473c0cde554fa31
    runtime         a98085007f1e3e82d52257aacebaac75aecf7a2ef5e7adc43721d48b3ce7d824

  A valid proof about the wrong model is still refused, because the
  commitment is checked before the proof. This is the downgrade defence.
```

### The full operator flow

```bash
export TVC_SECRET_KEY=$(openssl rand -hex 32)      # never passed in argv

tvc ceremony --model-id acme-llm-7b --version 2026.09 \
             --participant bitshala \
             --participant acme-labs \
             --participant independent-auditor \
             --out ceremony-out

tvc commit  --setup ceremony-out                   # BIP-340 sign → commitment.json
tvc prove   --setup ceremony-out --weight 7 --bias 3 --input 11
tvc verify  --setup ceremony-out --digest $(cat ceremony-out/vk_digest.hex)
tvc audit   --setup ceremony-out                   # re-derive digest from the key
```

### Publishing to Nostr

A commitment must exist before it can be broadcast. `tvc demo` writes one to
`demo-out/honest/commitment.json` and prints the throwaway key that signed it;
the operator flow above writes one to `ceremony-out/commitment.json`. Either works.

```bash
cd nostr-bridge && npm install

# after `tvc demo` — it prints the matching export line for you
export TVC_SECRET_KEY=<the key tvc demo printed>
npm run broadcast -- --commitment ../demo-out/honest/commitment.json

# after the operator flow, using your real ceremony key
npm run broadcast -- --commitment ../ceremony-out/commitment.json        # dry run
npm run broadcast -- --commitment ../ceremony-out/commitment.json --live

npm run fetch -- --address acme-llm-7b:2026.09 --author <consortium-pubkey>
```

`TVC_SECRET_KEY` must be the **same key** that signed the commitment, so the Nostr
event and the BIP-340 signature inside it resolve to one identity. Without it the
bridge generates an ephemeral key, still produces a valid event, and warns that a
wallet pinned to the ceremony key will ignore it.

`broadcast` **simulates by default** and prints the exact wire payload. `--live` is required to touch a relay, and it refuses to publish if the Nostr key does not match the BIP-340 signer inside the commitment — publishing a commitment from an identity a wallet is not pinned to is a silent no-op, so the tool treats it as an error rather than letting you believe you shipped.

---

## How this scores against the rubric

### Innovation

The novel claim is **structural, not incremental**: model integrity does not need a per-inference authority. Existing approaches all keep something on the hot path — an enclave quote, an attestation server, a reputation oracle. W-TVC observes that a Groth16 verifying key is a *function of circuit shape alone*, which makes it a legitimate permanent identity for a model version. Once that is true, the entire runtime trust apparatus collapses into a 32-byte constant, and a 32-byte constant is small enough to live on a censorship-resistant broadcast layer forever.

Three pieces that are individually known — trusted setup, addressable Nostr events, BIP-340 — compose into something that is not: **AI model identity with no issuing authority**. The consortium's ceremony key and its Nostr identity are literally the same secp256k1 key, so there is no certificate chain, no registry, and nothing to revoke.

### Completeness

Both phases are implemented and tested end to end, across two languages, with the artefacts of one consumed by the other.

| | |
|---|---|
| Rust | 2,431 lines across `tvc-core` + `tvc-cli` |
| TypeScript | 563 lines in `nostr-bridge` |
| Tests | 40 Rust unit + 1 doctest + 8 TypeScript = **49 passing** |
| Warnings | zero (`missing_docs = "deny"`, `unsafe_code = "forbid"`) |
| Dependencies | 10 direct Rust crates, 1 runtime npm package |

Real cryptography throughout: Groth16 over BN254 via `arkworks`, BIP-340 Schnorr over secp256k1 via `rust-bitcoin`, tagged SHA-256 via `bitcoin_hashes`, volatile zeroization via `zeroize`. Nothing in the verification path is stubbed.

### Use case

**Machine Money.** An agent holding a budget needs to know the model authorising its spend is the one it is paying for. W-TVC makes downgrade fraud detectable by the payer instead of auditable only by the seller. Bitcoin is the money that does not ask who you are; this is the model attestation that does not ask who you are either.

**Freedom Stack.** The commitment is a signed object, not a hosted record. Relays are interchangeable, and a relay that censors a commitment accomplishes nothing because any other relay serves the identical signed bytes. There is no issuer to subpoena and no registry to capture.

The concrete scenario driving the design: a UPI payment agent in India authorising a ₹4,200 transaction. The wallet resolves the digest once, caches it, and every later verification is local arithmetic — which matters on a phone, on a patchy connection, where a round trip to an attestation service is a failure mode.

### Scope

Deliberately narrow and honest about it. This repository ships the **protocol**: ceremony, commitment, transport, verification. It does not ship a production ZK-ML proving stack, because doing that credibly is a multi-year effort and claiming otherwise in a hackathon README would be the fastest way to lose an expert judge.

What that buys is a clean seam. The circuit is the one component a production deployment replaces, and **nothing downstream of it changes** — not the digest derivation, not the burn, not the signature, not the event format, not the wallet check. The protocol is the contribution; the circuit is a parameter.

### UI/UX

This is infrastructure, so the interface is a CLI and a wallet verdict — and both are designed rather than defaulted.

- **A rejection tells you which attack happened.** "Model substitution detected" and "the pairing check failed" are different messages with different remediation, because collapsing them into "invalid" is precisely how a downgrade hides.
- **Secrets never enter argv.** `TVC_SECRET_KEY` comes from the environment; process arguments are world-readable via `/proc` and land in shell history. The error message when it is unset tells you how to generate one.
- **Every command ends by printing the next one.** `ceremony` → `commit` → `broadcast` is discoverable without the README open.
- **Destructive and outward-facing actions are opt-in.** Broadcasting simulates unless you pass `--live`.
- **Exit codes are real** (`0` accept, `1` reject), so `tvc verify` drops into a CI pipeline or a shell conditional unchanged.

The wallet-facing surface reduces to one line a non-technical user can act on — *this response came from the model you are paying for*, or *it did not* — with the digest available for anyone who wants to check it themselves.

### Demo

`tvc demo` is the demo: one command, no arguments, no configuration, no network. It runs a genuine ceremony, proves a genuine inference, then **mounts the actual attack** — a second ceremony standing in for a downgraded model — and shows the rogue proof being accepted against its own key and refused against the committed one. The interesting frame for a judge is that the forgery is not malformed. It is a perfectly valid proof, rejected for the right reason.

---

## What is real, and what is scaffolding

Stated plainly, because a protocol that asks to be trusted should not have to be reverse-engineered to find its limits. This section is duplicated in the crate-level rustdoc.

**Real, and exercised by the test suite**

- Groth16 setup, proving, and verification over BN254 (`arkworks` 0.4)
- BIP-340 Schnorr signing and verification over secp256k1 (`rust-bitcoin` 0.33)
- Tagged, length-prefixed, domain-separated SHA-256 matching the BIP-340 construction
- Hash-chained ceremony transcript, with reorder and truncation both caught by tests
- Volatile zeroization of setup entropy across the full allocation capacity
- Commitment-before-proof verification order, including a test that a validly-proven substituted model is rejected
- Cross-language integration: the Rust CLI's BIP-340 signer key and the bridge's Nostr pubkey resolve to one identity

**Scaffolding, with the upgrade path documented in-tree**

- **The circuit** (`circuit.rs`) is an affine relation over `Fr`, not a neural network. It enforces the right *shape* of claim — one parameter pair must explain both the computation and the public commitment — but over four constraints instead of a weight tensor. Production replaces it with a quantised arithmetic circuit plus a Poseidon or Merkle commitment to the real weights.
- **The ceremony** (`mpc_setup.rs`) aggregates participant entropy into one seed on one machine. It is **not** a Phase-2 MPC. The honest security claim today is *"trust the operator, audit the transcript"*, not the 1-of-N claim a real MPC delivers. A true Phase-2 ceremony has each participant apply their contribution locally, publish a proof of correct contribution, and destroy their own share; the interfaces here are shaped for that substitution.

## Threat model

**Defended.** Silent model substitution and token downgrading. Tampered public outputs. Forged or altered parameter commitments (BIP-340 over every field). Commitments from an unpinned key. Relay censorship and relay-level tampering. Transcript reordering, truncation, and extension.

**Not defended, and why**

| Gap | Status |
|---|---|
| A ceremony operator who retains the combined entropy | The Phase-2 MPC upgrade above. Today's mitigation is an auditable transcript and an ephemeral ceremony machine. |
| Register and stack residue during setup | `arkworks` copies field elements internally, outside any destructor's reach. Run the ceremony on a machine you destroy afterwards. |
| Swap, hibernation, core dumps | Disable both for the ceremony process. `panic = "abort"` means destructors do not run on panic, so core-dump hygiene is what covers that path. |
| Descriptor tampering between `ceremony` and `commit` | Caught. The recorded model-binding digest is recomputed at signing time and must match. |
| A model whose *weights* change without a new ceremony | Out of scope by construction. The circuit binds parameters to the commitment; binding the commitment to real-world model behaviour needs the production circuit. |
| Kind 30200 is addressable, so a later event replaces an earlier one | A deliberate trade for lookup by `model:version`. `npm run fetch` warns when relays serve divergent digests for one address. Wallets should pin the digest on first use. |

## Repository layout

```
.
├── Cargo.toml              workspace: shared versions, hardened release profile
├── tvc-core/               the cryptographic core, no I/O
│   └── src/
│       ├── lib.rs          crate docs, module map, end-to-end doctest
│       ├── circuit.rs      the committed inference relation (R1CS)
│       ├── mpc_setup.rs    Phase 1: ceremony, transcript, digest derivation
│       ├── crypto_burn.rs  toxic-waste destruction and burn attestation
│       ├── proof_verifier.rs  Phase 2: proving, verification, BIP-340 commitments
│       ├── digest.rs       BIP-340 tagged hashing, domain separation
│       ├── hex.rs          strict lowercase hex codec
│       └── error.rs        error taxonomy
├── tvc-cli/                the `tvc` binary
│   └── src/
│       ├── main.rs         ceremony · commit · prove · verify · audit · demo
│       └── json.rs         dependency-free JSON writer
└── nostr-bridge/           TypeScript, Nostr transport
    └── src/
        ├── commitment.ts   strict parsing and validation of commitment.json
        ├── event.ts        kind 30200 construction and signing
        ├── broadcast.ts    publish (dry-run by default)
        ├── fetch.ts        wallet-side resolution and reconciliation
        └── bridge.test.ts  8 tests
```

## Event specification — kind `30200`

Addressable (NIP-01 range `30000`–`39999`), so a commitment is addressed by `(kind, pubkey, d)` and a wallet resolves the current commitment for a model version without scanning history.

```jsonc
{
  "kind": 30200,
  "tags": [
    ["d",          "acme-llm-7b:2026.09"],   // addressable identifier
    ["vk",         "<64 hex>"],              // the 32-byte verification digest
    ["model",      "acme-llm-7b"],
    ["ver",        "2026.09"],
    ["alg",        "groth16-bn254"],
    ["transcript", "<64 hex>"],              // ceremony transcript digest
    ["burn",       "<64 hex>"],              // toxic-waste burn attestation
    ["signer",     "<64 hex>"],              // x-only consortium key
    ["bip340",     "<128 hex>"],             // signature over the commitment sighash
    ["protocol",   "w-tvc/1"],
    ["t",          "w-tvc"]
  ],
  "content": "{ ...the same commitment as JSON... }"
}
```

The BIP-340 signature is over a tagged sighash of the commitment fields, **independent of Nostr**. The commitment therefore verifies identically whether it arrives from a relay, a web page, or a USB stick — the relay is transport, not authority. `fetch.ts` refuses any event whose tags disagree with its content.

## Design decisions worth defending

- **Tagged hashing everywhere.** Every digest is domain-separated with a BIP-340 tagged hash, and every message part is length-prefixed. Plain concatenation is ambiguous — `("ab","c")` and `("a","bc")` collide — which would let a participant identifier absorb adjacent bytes and forge a transcript entry.
- **The digest is a pure function of the key.** Model metadata is *not* mixed in. A wallet recomputes the digest from the key it was handed and nothing else; binding key to claimed model identity is the signature's job. Separating them means the arithmetic check needs no metadata.
- **Signing key from the environment, aux randomness passed explicitly.** The signing path has no hidden entropy source, which makes it reproducible under test and auditable in production.
- **Model identifiers are validated at the boundary.** `model_id` and `version`
  accept only ASCII alphanumerics plus `-`, `_` and `.`. Three exclusions have
  concrete reasons: a `:` would make the `<model_id>:<version>` address ambiguous,
  so a wallet splitting the Nostr `d` tag would recover a different pair than was
  frozen; a newline would corrupt the line-delimited descriptor file, letting a
  ceremony be signed under an identity it never froze; whitespace and control
  characters let two identical-looking identifiers hash differently. Rejecting at
  the boundary is cheaper than making every consumer defensive.
- **The commitment is bound to the ceremony, not to a text file.** `tvc ceremony`
  records a digest over the full descriptor, and `tvc commit` recomputes it from
  what it read back and refuses to sign on mismatch. Identity cannot drift between
  freezing a key and signing the claim about it, whatever the cause.
- **Ten Rust dependencies, one npm runtime dependency.** Hex and JSON are ~40 auditable lines each rather than transitive trees, because they sit on the trust boundary.

## Roadmap

1. Phase-2 MPC with per-participant contribution proofs → genuine 1-of-N trust
2. Quantised inference circuit over a real weight tensor, with a Poseidon commitment
3. `SPOT Wallet` reference consumer: resolve, pin on first use, verify offline
4. NIP draft for kind 30200 submitted to `nostr-protocol/nips`
5. Recursive proof aggregation so a batch of inferences verifies in one pairing check

## License

MIT. See [`LICENSE`](LICENSE).
__W_TVC_FILE_0__

echo "  LICENSE"
cat > 'LICENSE' <<'__W_TVC_FILE_1__'
MIT License

Copyright (c) 2026 Kartikeya Sharma and W-TVC Protocol Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
__W_TVC_FILE_1__

echo "  .gitignore"
cat > '.gitignore' <<'__W_TVC_FILE_2__'
# ---------------------------------------------------------------------------
# Secrets and key material — highest priority, listed first and deliberately
# broad. A ceremony repository that leaks a signing key is worse than useless:
# an attacker who holds it can sign parameter commitments for models that never
# went through a ceremony, and every wallet pinned to that key will believe them.
# ---------------------------------------------------------------------------
*.key
*.pem
*.p12
*.pfx
*.jks
*.keystore
*.asc
*.gpg
*.kdbx
*.secret
*.seed
*.entropy

# Nostr and Bitcoin key encodings, in every spelling we could think of.
nsec*
*nsec*
*.nsec
privkey*
*privkey*
priv_key*
secret_key*
secretkey*
seckey*
*.xprv
xprv*
mnemonic*
seed_phrase*
wallet.dat

# Environment files. .env.example is explicitly re-included below.
.env
.env.*
*.env
!.env.example

# ---------------------------------------------------------------------------
# Ceremony artefacts and toxic waste.
# Structural keys are reproducible from a transcript and are large; entropy must
# never reach disk at all. Anything a ceremony writes stays local by default.
# ---------------------------------------------------------------------------
ceremony-out/
demo-out/
*-ceremony-out/
toxic*
*toxic*
waste/
contributions/
*.ptau
*.zkey
proving_key.bin
verifying_key.bin
proof.bin
public_inputs.txt
commitment.json
transcript.json
*_digest.hex
vk_digest.hex

# ---------------------------------------------------------------------------
# State, logs, and scratch output.
# ---------------------------------------------------------------------------
*.log
logs/
*.pid
*.seed.json
state/
.state
*.sqlite
*.sqlite3
*.db
tmp/
temp/
scratch/
out/

# ---------------------------------------------------------------------------
# Rust.
# Cargo.lock is intentionally NOT ignored: this workspace ships binaries, and a
# committed lockfile is what makes a judge's build byte-for-byte reproducible.
# ---------------------------------------------------------------------------
target/
**/*.rs.bk
*.pdb
.cargo/config.toml

# ---------------------------------------------------------------------------
# Node and TypeScript.
# ---------------------------------------------------------------------------
node_modules/
dist/
build/
coverage/
.npm
.yarn/
.pnp.*
*.tsbuildinfo
npm-debug.log*
yarn-error.log*
pnpm-debug.log*

# ---------------------------------------------------------------------------
# Editors and operating systems.
# ---------------------------------------------------------------------------
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
Thumbs.db
desktop.ini
.idea/
.vscode/
!.vscode/extensions.json
*.swp
*.swo
*~
.claude/
__W_TVC_FILE_2__

echo "  .env.example"
cat > '.env.example' <<'__W_TVC_FILE_3__'
# Copy to .env and fill in. .env is git-ignored; .env.example is not.
#
# Ceremony signing key: 64 lowercase hex characters (a 32-byte secp256k1 scalar).
# Used by `tvc commit` to sign the parameter commitment, and by the Nostr bridge
# as the event signing key. The same key MUST serve both roles, so that the
# BIP-340 signature inside the commitment and the Nostr event signature resolve
# to one identity a wallet can pin.
#
# Generate with:  openssl rand -hex 32
TVC_SECRET_KEY=
__W_TVC_FILE_3__

echo "  Cargo.toml"
cat > 'Cargo.toml' <<'__W_TVC_FILE_4__'
[workspace]
members = ["tvc-core", "tvc-cli"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.75"
license = "MIT"
repository = "https://github.com/sha256rma/w-tvc-protocol"
homepage = "https://github.com/sha256rma/w-tvc-protocol"
authors = ["W-TVC Protocol Contributors"]

[workspace.dependencies]
ark-bn254 = { version = "0.4", default-features = false, features = ["curve"] }
ark-ff = { version = "0.4", default-features = false }
ark-groth16 = { version = "0.4", default-features = false }
ark-relations = { version = "0.4", default-features = false }
ark-serialize = { version = "0.4", default-features = false }
ark-snark = { version = "0.4", default-features = false }
ark-std = { version = "0.4", default-features = false, features = ["std"] }
bitcoin_hashes = { version = "1.2", default-features = false, features = ["std"] }
secp256k1 = { version = "0.33", default-features = false, features = ["std"] }
zeroize = { version = "1.9", default-features = false, features = ["std", "zeroize_derive"] }

[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
panic = "abort"
debug = false
strip = "symbols"
__W_TVC_FILE_4__

echo "  Cargo.lock"
cat > 'Cargo.lock' <<'__W_TVC_FILE_LOCK__'
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "ahash"
version = "0.8.12"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "5a15f179cd60c4584b8a8c596927aadc462e27f2ca70c04e0071964a73ba7a75"
dependencies = [
 "cfg-if",
 "once_cell",
 "version_check",
 "zerocopy",
]

[[package]]
name = "anstream"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "824a212faf96e9acacdbd09febd34438f8f711fb84e09a8916013cd7815ca28d"
dependencies = [
 "anstyle",
 "anstyle-parse",
 "anstyle-query",
 "anstyle-wincon",
 "colorchoice",
 "is_terminal_polyfill",
 "utf8parse",
]

[[package]]
name = "anstyle"
version = "1.0.14"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "940b3a0ca603d1eade50a4846a2afffd5ef57a9feac2c0e2ec2e14f9ead76000"

[[package]]
name = "anstyle-parse"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "52ce7f38b242319f7cabaa6813055467063ecdc9d355bbb4ce0c68908cd8130e"
dependencies = [
 "utf8parse",
]

[[package]]
name = "anstyle-query"
version = "1.1.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "40c48f72fd53cd289104fc64099abca73db4166ad86ea0b4341abe65af83dadc"
dependencies = [
 "windows-sys",
]

[[package]]
name = "anstyle-wincon"
version = "3.0.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "291e6a250ff86cd4a820112fb8898808a366d8f9f58ce16d1f538353ad55747d"
dependencies = [
 "anstyle",
 "once_cell_polyfill",
 "windows-sys",
]

[[package]]
name = "ark-bn254"
version = "0.4.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a22f4561524cd949590d78d7d4c5df8f592430d221f7f3c9497bbafd8972120f"
dependencies = [
 "ark-ec",
 "ark-ff",
 "ark-std",
]

[[package]]
name = "ark-crypto-primitives"
version = "0.4.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1f3a13b34da09176a8baba701233fdffbaa7c1b1192ce031a3da4e55ce1f1a56"
dependencies = [
 "ark-ec",
 "ark-ff",
 "ark-relations",
 "ark-serialize",
 "ark-snark",
 "ark-std",
 "blake2",
 "derivative",
 "digest",
 "sha2",
]

[[package]]
name = "ark-ec"
version = "0.4.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "defd9a439d56ac24968cca0571f598a61bc8c55f71d50a89cda591cb750670ba"
dependencies = [
 "ark-ff",
 "ark-poly",
 "ark-serialize",
 "ark-std",
 "derivative",
 "hashbrown",
 "itertools",
 "num-traits",
 "zeroize",
]

[[package]]
name = "ark-ff"
version = "0.4.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ec847af850f44ad29048935519032c33da8aa03340876d351dfab5660d2966ba"
dependencies = [
 "ark-ff-asm",
 "ark-ff-macros",
 "ark-serialize",
 "ark-std",
 "derivative",
 "digest",
 "itertools",
 "num-bigint",
 "num-traits",
 "paste",
 "rustc_version",
 "zeroize",
]

[[package]]
name = "ark-ff-asm"
version = "0.4.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3ed4aa4fe255d0bc6d79373f7e31d2ea147bcf486cba1be5ba7ea85abdb92348"
dependencies = [
 "quote",
 "syn 1.0.109",
]

[[package]]
name = "ark-ff-macros"
version = "0.4.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "7abe79b0e4288889c4574159ab790824d0033b9fdcb2a112a3182fac2e514565"
dependencies = [
 "num-bigint",
 "num-traits",
 "proc-macro2",
 "quote",
 "syn 1.0.109",
]

[[package]]
name = "ark-groth16"
version = "0.4.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "20ceafa83848c3e390f1cbf124bc3193b3e639b3f02009e0e290809a501b95fc"
dependencies = [
 "ark-crypto-primitives",
 "ark-ec",
 "ark-ff",
 "ark-poly",
 "ark-relations",
 "ark-serialize",
 "ark-std",
]

[[package]]
name = "ark-poly"
version = "0.4.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d320bfc44ee185d899ccbadfa8bc31aab923ce1558716e1997a1e74057fe86bf"
dependencies = [
 "ark-ff",
 "ark-serialize",
 "ark-std",
 "derivative",
 "hashbrown",
]

[[package]]
name = "ark-relations"
version = "0.4.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "00796b6efc05a3f48225e59cb6a2cda78881e7c390872d5786aaf112f31fb4f0"
dependencies = [
 "ark-ff",
 "ark-std",
 "tracing",
]

[[package]]
name = "ark-serialize"
version = "0.4.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "adb7b85a02b83d2f22f89bd5cac66c9c89474240cb6207cb1efc16d098e822a5"
dependencies = [
 "ark-serialize-derive",
 "ark-std",
 "digest",
 "num-bigint",
]

[[package]]
name = "ark-serialize-derive"
version = "0.4.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ae3281bc6d0fd7e549af32b52511e1302185bd688fd3359fa36423346ff682ea"
dependencies = [
 "proc-macro2",
 "quote",
 "syn 1.0.109",
]

[[package]]
name = "ark-snark"
version = "0.4.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "84d3cc6833a335bb8a600241889ead68ee89a3cf8448081fb7694c0fe503da63"
dependencies = [
 "ark-ff",
 "ark-relations",
 "ark-serialize",
 "ark-std",
]

[[package]]
name = "ark-std"
version = "0.4.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "94893f1e0c6eeab764ade8dc4c0db24caf4fe7cbbaafc0eba0a9030f447b5185"
dependencies = [
 "num-traits",
 "rand 0.8.8",
]

[[package]]
name = "arrayvec"
version = "0.7.8"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d3fb67a6e08acf24fdeccbac2cb6ac4305825bd1f117462e0e6f2f193345ad56"

[[package]]
name = "autocfg"
version = "1.5.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f2032f911046de80f0a198e0901378627c33f59ea0ac00e363d481118bd70a53"

[[package]]
name = "bitcoin-consensus-encoding"
version = "1.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "6712f9c6fd6785b3b270884e57c441c403dc5d7e19ca45368c97c7a1de3000ec"
dependencies = [
 "bitcoin-internals",
]

[[package]]
name = "bitcoin-internals"
version = "0.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d573f4cf32996a8dce612e4348cece65a241f1882ed594047c9ba348e8869fa5"

[[package]]
name = "bitcoin_hashes"
version = "1.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "5304e53726dbe5f93141535e102ed97b5bf4714fbecefdda8f9fb98d7fdaff0e"
dependencies = [
 "bitcoin-consensus-encoding",
 "bitcoin-internals",
 "hex-conservative",
]

[[package]]
name = "blake2"
version = "0.10.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "46502ad458c9a52b69d4d4d32775c788b7a1b85e8bc9d482d92250fc0e3f8efe"
dependencies = [
 "digest",
]

[[package]]
name = "block-buffer"
version = "0.10.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3078c7629b62d3f0439517fa394996acacc5cbc91c5a20d8c658e77abd503a71"
dependencies = [
 "generic-array",
]

[[package]]
name = "cc"
version = "1.4.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a3eb0f42d6c360dc3f8a821f6bf2fdea7f72bfd36b3076eb0e6d1e9e0752fff4"
dependencies = [
 "find-msvc-tools",
 "shlex",
]

[[package]]
name = "cfg-if"
version = "1.0.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801"

[[package]]
name = "clap"
version = "4.6.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "473c7e07f409a8d772161724aa8db6a765a2532a70f9667eeb7b49d3d02fbdca"
dependencies = [
 "clap_builder",
 "clap_derive",
]

[[package]]
name = "clap_builder"
version = "4.6.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "7b48fea5a88e9ae728a2dcbedbfc0e730f7d60da42e1cb049a83c9fb8b789889"
dependencies = [
 "anstream",
 "anstyle",
 "clap_lex",
 "strsim",
]

[[package]]
name = "clap_derive"
version = "4.6.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d012d2b9d65aca7f18f4d9878a045bc17899bba951561ba5ec3c2ba1eed9a061"
dependencies = [
 "heck",
 "proc-macro2",
 "quote",
 "syn 3.0.5",
]

[[package]]
name = "clap_lex"
version = "1.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c8d4a3bb8b1e0c1050499d1815f5ab16d04f0959b233085fb31653fbfc9d98f9"

[[package]]
name = "colorchoice"
version = "1.0.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1d07550c9036bf2ae0c684c4297d503f838287c83c53686d05370d0e139ae570"

[[package]]
name = "cpufeatures"
version = "0.2.17"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280"
dependencies = [
 "libc",
]

[[package]]
name = "crypto-common"
version = "0.1.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "78c8292055d1c1df0cce5d180393dc8cce0abec0a7102adb6c7b1eef6016d60a"
dependencies = [
 "generic-array",
 "typenum",
]

[[package]]
name = "derivative"
version = "2.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fcc3dd5e9e9c0b295d6e1e4d811fb6f157d5ffd784b8d202fc62eac8035a770b"
dependencies = [
 "proc-macro2",
 "quote",
 "syn 1.0.109",
]

[[package]]
name = "digest"
version = "0.10.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9ed9a281f7bc9b7576e61468ba615a66a5c8cfdff42420a70aa82701a3b1e292"
dependencies = [
 "block-buffer",
 "crypto-common",
 "subtle",
]

[[package]]
name = "either"
version = "1.18.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "252afb9ae5eaa683babdc6a068b3f5726eb19e05070c731f9b2a23a7c3e8ed34"

[[package]]
name = "find-msvc-tools"
version = "0.1.12"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3e0f1c7c3a72c66fd80abe965175f7523475c0489a87d3ff9d6e8c87d87a9d2d"

[[package]]
name = "generic-array"
version = "0.14.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "85649ca51fd72272d7821adaf274ad91c288277713d9c18820d8499a7ff69e9a"
dependencies = [
 "typenum",
 "version_check",
]

[[package]]
name = "getrandom"
version = "0.3.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "899def5c37c4fd7b2664648c28120ecec138e4d395b459e5ca34f9cce2dd77fd"
dependencies = [
 "cfg-if",
 "libc",
 "r-efi",
 "wasip2",
]

[[package]]
name = "hashbrown"
version = "0.13.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "43a3c133739dddd0d2990f9a4bdf8eb4b21ef50e4851ca85ab661199821d510e"
dependencies = [
 "ahash",
]

[[package]]
name = "heck"
version = "0.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2304e00983f87ffb38b55b444b5e3b60a884b5d30c0fca7d82fe33449bbe55ea"

[[package]]
name = "hex-conservative"
version = "1.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "271e0d19bcb473b6675739a2b536076b24a082316cb5199ad918edce10c599e8"
dependencies = [
 "arrayvec",
]

[[package]]
name = "is_terminal_polyfill"
version = "1.70.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a6cb138bb79a146c1bd460005623e142ef0181e3d0219cb493e02f7d08a35695"

[[package]]
name = "itertools"
version = "0.10.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b0fd2260e829bddf4cb6ea802289de2f86d6a7a690192fbe91b3f46e0f2c8473"
dependencies = [
 "either",
]

[[package]]
name = "libc"
version = "0.2.189"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2"

[[package]]
name = "num-bigint"
version = "0.4.8"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c89e69e7e0f03bea5ef08013795c25018e101932225a656383bd384495ecc367"
dependencies = [
 "num-integer",
 "num-traits",
]

[[package]]
name = "num-integer"
version = "0.1.47"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "7ce2d95d4b3734dc35aa2f45e1aa22cd416814592a4f9d9205e11affd5b8e10b"
dependencies = [
 "num-traits",
]

[[package]]
name = "num-traits"
version = "0.2.19"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841"
dependencies = [
 "autocfg",
]

[[package]]
name = "once_cell"
version = "1.21.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50"

[[package]]
name = "once_cell_polyfill"
version = "1.70.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "384b8ab6d37215f3c5301a95a4accb5d64aa607f1fcb26a11b5303878451b4fe"

[[package]]
name = "paste"
version = "1.0.15"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "57c0d7b74b563b49d38dae00a0c37d4d6de9b432382b2892f0574ddcae73fd0a"

[[package]]
name = "pin-project-lite"
version = "0.2.17"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a89322df9ebe1c1578d689c92318e070967d1042b512afbe49518723f4e6d5cd"

[[package]]
name = "ppv-lite86"
version = "0.2.21"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "85eae3c4ed2f50dcfe72643da4befc30deadb458a9b590d720cde2f2b1e97da9"
dependencies = [
 "zerocopy",
]

[[package]]
name = "proc-macro2"
version = "1.0.107"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9"
dependencies = [
 "unicode-ident",
]

[[package]]
name = "quote"
version = "1.0.47"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001"
dependencies = [
 "proc-macro2",
]

[[package]]
name = "r-efi"
version = "5.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "69cdb34c158ceb288df11e18b4bd39de994f6657d83847bdffdbd7f346754b0f"

[[package]]
name = "rand"
version = "0.8.8"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e058c7de0b26af77780c769414d6257830bb240f3c38477dbc2c16e5f54d6d4c"
dependencies = [
 "rand_chacha 0.3.1",
 "rand_core 0.6.4",
]

[[package]]
name = "rand"
version = "0.9.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b9ef1d0d795eb7d84685bca4f72f3649f064e6641543d3a8c415898726a57b41"
dependencies = [
 "rand_chacha 0.9.0",
 "rand_core 0.9.5",
]

[[package]]
name = "rand_chacha"
version = "0.3.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e6c10a63a0fa32252be49d21e7709d4d4baf8d231c2dbce1eaa8141b9b127d88"
dependencies = [
 "ppv-lite86",
 "rand_core 0.6.4",
]

[[package]]
name = "rand_chacha"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d3022b5f1df60f26e1ffddd6c66e8aa15de382ae63b3a0c1bfc0e4d3e3f325cb"
dependencies = [
 "ppv-lite86",
 "rand_core 0.9.5",
]

[[package]]
name = "rand_core"
version = "0.6.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ec0be4795e2f6a28069bec0b5ff3e2ac9bafc99e6a9a7dc3547996c5c816922c"

[[package]]
name = "rand_core"
version = "0.9.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "76afc826de14238e6e8c374ddcc1fa19e374fd8dd986b0d2af0d02377261d83c"
dependencies = [
 "getrandom",
]

[[package]]
name = "rustc_version"
version = "0.4.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cfcb3a22ef46e85b45de6ee7e79d063319ebb6594faafcf1c225ea92ab6e9b92"
dependencies = [
 "semver",
]

[[package]]
name = "secp256k1"
version = "0.33.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d7f404a8dab7a7a5a631e741d8699aa9c8e1d689fc26ccf897c7187565490b69"
dependencies = [
 "rand 0.9.5",
 "secp256k1-sys",
]

[[package]]
name = "secp256k1-sys"
version = "0.14.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f6b2992d4a3cd244539a7d5d0966aadbe5ca7fb868a5d7e38c29499b9e709bbd"
dependencies = [
 "cc",
]

[[package]]
name = "semver"
version = "1.0.28"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd"

[[package]]
name = "sha2"
version = "0.10.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283"
dependencies = [
 "cfg-if",
 "cpufeatures",
 "digest",
]

[[package]]
name = "shlex"
version = "2.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba"

[[package]]
name = "strsim"
version = "0.11.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "7da8b5736845d9f2fcb837ea5d9e2628564b3b043a70948a3f0b778838c5fb4f"

[[package]]
name = "subtle"
version = "2.6.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292"

[[package]]
name = "syn"
version = "1.0.109"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "72b64191b275b66ffe2469e8af2c1cfe3bafa67b529ead792a6d0160888b4237"
dependencies = [
 "proc-macro2",
 "quote",
 "unicode-ident",
]

[[package]]
name = "syn"
version = "2.0.119"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297"
dependencies = [
 "proc-macro2",
 "quote",
 "unicode-ident",
]

[[package]]
name = "syn"
version = "3.0.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "12df2e0110f65b775f769bb17ef989067a1d931b2eb822bd4346631eeada89f9"
dependencies = [
 "proc-macro2",
 "quote",
 "unicode-ident",
]

[[package]]
name = "tracing"
version = "0.1.44"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "63e71662fa4b2a2c3a26f570f037eb95bb1f85397f3cd8076caed2f026a6d100"
dependencies = [
 "pin-project-lite",
 "tracing-core",
]

[[package]]
name = "tracing-core"
version = "0.1.36"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "db97caf9d906fbde555dd62fa95ddba9eecfd14cb388e4f491a66d74cd5fb79a"

[[package]]
name = "tvc-cli"
version = "0.1.0"
dependencies = [
 "ark-bn254",
 "ark-ff",
 "clap",
 "getrandom",
 "tvc-core",
]

[[package]]
name = "tvc-core"
version = "0.1.0"
dependencies = [
 "ark-bn254",
 "ark-ff",
 "ark-groth16",
 "ark-relations",
 "ark-serialize",
 "ark-snark",
 "ark-std",
 "bitcoin_hashes",
 "secp256k1",
 "zeroize",
]

[[package]]
name = "typenum"
version = "1.20.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b6f5e870be6c3b371b77fe0ee0bafb859fa4964b4404c27de1d380043c4dda20"

[[package]]
name = "unicode-ident"
version = "1.0.24"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e6e4313cd5fcd3dad5cafa179702e2b244f760991f45397d14d4ebf38247da75"

[[package]]
name = "utf8parse"
version = "0.2.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "06abde3611657adf66d383f00b093d7faecc7fa57071cce2578660c9f1010821"

[[package]]
name = "version_check"
version = "0.9.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0b928f33d975fc6ad9f86c8f283853ad26bdd5b10b7f1542aa2fa15e2289105a"

[[package]]
name = "wasip2"
version = "1.0.4+wasi-0.2.12"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b67efb37e106e55ce722a510d6b5f9c17f083e5fc79afc2badeb12cc313d9487"
dependencies = [
 "wit-bindgen",
]

[[package]]
name = "windows-link"
version = "0.2.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5"

[[package]]
name = "windows-sys"
version = "0.61.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc"
dependencies = [
 "windows-link",
]

[[package]]
name = "wit-bindgen"
version = "0.57.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1ebf944e87a7c253233ad6766e082e3cd714b5d03812acc24c318f549614536e"

[[package]]
name = "zerocopy"
version = "0.8.57"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d35102a9f36d089ccae9e4c6802bc118be4487b80aaffc0ab4e0cf5ce92d2873"
dependencies = [
 "zerocopy-derive",
]

[[package]]
name = "zerocopy-derive"
version = "0.8.57"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "146c01f5ab44258da43cf276c74a2763db2ff3969c9c652c3f2de07041d0b2bc"
dependencies = [
 "proc-macro2",
 "quote",
 "syn 2.0.119",
]

[[package]]
name = "zeroize"
version = "1.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e"
dependencies = [
 "zeroize_derive",
]

[[package]]
name = "zeroize_derive"
version = "1.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3c50655cbb0fe3fc43170059e702f1ce5e19b84cec58dc87b037a09935c2f328"
dependencies = [
 "proc-macro2",
 "quote",
 "syn 2.0.119",
]
__W_TVC_FILE_LOCK__

echo "  tvc-core/Cargo.toml"
cat > 'tvc-core/Cargo.toml' <<'__W_TVC_FILE_5__'
[package]
name = "tvc-core"
description = "Weight Threshold Verification Ceremony: trusted-setup, parameter commitment and zero-knowledge inference verification primitives."
keywords = ["zero-knowledge", "groth16", "nostr", "bitcoin", "attestation"]
categories = ["cryptography"]
readme = "../README.md"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true

[dependencies]
ark-bn254.workspace = true
ark-ff.workspace = true
ark-groth16.workspace = true
ark-relations.workspace = true
ark-serialize.workspace = true
ark-snark.workspace = true
ark-std.workspace = true
bitcoin_hashes.workspace = true
secp256k1.workspace = true
zeroize.workspace = true

[lints.rust]
missing_docs = "deny"
unsafe_code = "forbid"
__W_TVC_FILE_5__

echo "  tvc-core/src/lib.rs"
cat > 'tvc-core/src/lib.rs' <<'__W_TVC_FILE_6__'
//! # W-TVC Protocol — Weight Threshold Verification Ceremony
//!
//! Cryptographic core for proving that an AI inference was served by the model
//! its provider claims, without a hardware TEE, a per-request attestation
//! service, or any trusted party on the runtime path.
//!
//! ## The problem
//!
//! A wallet asking a remote model to authorise a payment has no way to tell which
//! model answered. The provider can silently route the request to a cheaper
//! distillation — *token downgrading* — and bill for the flagship. Today the
//! usual answer is a hardware enclave: trust Intel, AMD, or NVIDIA to vouch for
//! the binary. That replaces a trusted provider with a trusted silicon vendor,
//! and a decade of enclave CVEs makes that a poor trade. It also cannot work for
//! a model served from hardware you do not control.
//!
//! ## The approach
//!
//! Move the trust from silicon to arithmetic, and do the expensive part once.
//!
//! | Phase | When | What happens |
//! |---|---|---|
//! | **Genesis** | Once per model version | A ceremony freezes the circuit's structural parameters into a permanent 32-byte digest, destroys the setup entropy, and publishes a signed commitment to Nostr relays. |
//! | **Runtime** | Every inference | The provider emits a zero-knowledge proof. The wallet fetches the digest from any relay and verifies the proof against it locally. |
//!
//! Groth16's trusted setup depends only on the *shape* of the constraint system,
//! never on a witness. The shape is fixed by the model architecture, so one
//! verifying key covers every inference that model version will ever serve. That
//! is what makes a write-once commitment sufficient and keeps the runtime path
//! free of any authority to ask.
//!
//! ## Module map
//!
//! | Module | Role |
//! |---|---|
//! | [`circuit`] | The committed inference relation as an R1CS. |
//! | [`mpc_setup`] | Phase 1: the ceremony, the transcript, the digest. |
//! | [`crypto_burn`] | Destruction of setup entropy and its attestation. |
//! | [`proof_verifier`] | Phase 2: proving, verification, BIP-340 commitments. |
//! | [`digest`] | BIP-340 tagged hashing and domain separation. |
//! | [`hex`] | Strict lowercase hex codec used on the relay boundary. |
//! | [`error`] | The error taxonomy. |
//!
//! ## What is real and what is scaffolding
//!
//! Honesty about scope is load-bearing for a protocol that asks to be trusted, so
//! this is stated in the code and not only in the README.
//!
//! **Real and exercised by the test suite.** Groth16 setup, proving, and
//! verification over BN254 via `arkworks`. BIP-340 Schnorr signing and
//! verification over secp256k1. Tagged, length-prefixed, domain-separated
//! hashing. The hash-chained ceremony transcript and its tamper checks. Volatile
//! zeroization of setup entropy. The commitment-before-proof verification order,
//! including a test that a validly-proven *substituted* model is rejected.
//!
//! **Scaffolding, with a documented upgrade path.** Two things.
//! [`circuit::InferenceCircuit`] is an affine relation over `Fr`, not a neural
//! network; a production deployment replaces it with a quantised circuit over the
//! real weight tensor. [`mpc_setup::run_ceremony`] aggregates participant entropy
//! on one machine rather than running a Phase-2 MPC, so its honest claim today is
//! "trust the operator, audit the transcript", not 1-of-N. Neither substitution
//! changes any interface downstream of [`mpc_setup::CeremonyOutput`].
//!
//! ## End-to-end example
//!
//! ```
//! use tvc_core::circuit::InferenceCircuit;
//! use tvc_core::mpc_setup::{field_from_u64, run_ceremony, ModelDescriptor, ParticipantContribution};
//! use tvc_core::proof_verifier::{prove_inference, verify_inference, ParameterCommitment};
//!
//! let setup = run_ceremony(
//!     ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 7_000_000_000),
//!     vec![
//!         ParticipantContribution::new("bitshala", [1u8; 32]),
//!         ParticipantContribution::new("acme-labs", [2u8; 32]),
//!     ],
//! )?;
//!
//! assert!(setup.transcript.verify_chain());
//!
//! let commitment = ParameterCommitment::new(
//!     "acme-llm-7b",
//!     "2026.09",
//!     setup.vk_digest,
//!     setup.transcript.final_digest,
//!     setup.burn.attestation_digest,
//! );
//! let signed = commitment.sign(&[0x11; 32], &[0x22; 32])?;
//! signed.verify()?;
//!
//! let proof = prove_inference(
//!     &setup.proving_key,
//!     field_from_u64(7),
//!     field_from_u64(3),
//!     field_from_u64(11),
//!     [42u8; 32],
//! )?;
//!
//! let report = verify_inference(
//!     &setup.verifying_key,
//!     &signed.commitment.vk_digest,
//!     &proof.public_inputs,
//!     &proof.proof,
//! )?;
//! assert!(report.accepted());
//!
//! let _ = InferenceCircuit::blueprint();
//! # Ok::<(), tvc_core::error::TvcError>(())
//! ```

#![doc(html_root_url = "https://docs.rs/tvc-core/0.1.0")]

pub mod circuit;
pub mod crypto_burn;
pub mod digest;
pub mod error;
pub mod hex;
pub mod mpc_setup;
pub mod proof_verifier;

pub use circuit::{InferenceCircuit, PUBLIC_INPUT_ARITY};
pub use crypto_burn::{BurnAttestation, ToxicWaste};
pub use error::{Result, TvcError};
pub use mpc_setup::{
    derive_vk_digest, field_from_u64, run_ceremony, CeremonyOutput, CeremonyTranscript,
    ContributionRecord, ModelDescriptor, ParticipantContribution, SCHEME_TAG,
};
pub use proof_verifier::{
    prove_inference, verify_inference, InferenceProof, ParameterCommitment, SignedCommitment,
    VerificationReport,
};

/// Semantic version of the protocol this crate implements.
pub const PROTOCOL_VERSION: &str = "w-tvc/1";

/// Nostr event kind carrying a signed parameter commitment.
///
/// Chosen from the addressable range (`30000`–`39999`) defined by NIP-01, so a
/// commitment is addressed by `(kind, pubkey, d)` and a wallet can always resolve
/// the current commitment for a model version without scanning history.
pub const NOSTR_COMMITMENT_KIND: u16 = 30200;
__W_TVC_FILE_6__

echo "  tvc-core/src/circuit.rs"
cat > 'tvc-core/src/circuit.rs' <<'__W_TVC_FILE_7__'
//! The committed inference relation, expressed as a Rank-1 Constraint System.
//!
//! # What this circuit actually proves
//!
//! W-TVC's security claim is not "an AI produced this number". It is the
//! strictly narrower and far more checkable claim:
//!
//! > *The same parameters that are bound by the public commitment are the
//! > parameters that transformed this input into this output.*
//!
//! That claim is what defeats token-downgrading. A provider who silently swaps a
//! flagship model for a cheaper distillation still has to produce a proof whose
//! public commitment input matches the digest frozen at ceremony time, and the
//! substituted parameters will not satisfy both halves of the relation at once.
//!
//! # The relation
//!
//! Private witness: `weight`, `bias`.
//! Public inputs, in allocation order: `input`, `output`, `commitment`.
//!
//! ```text
//!   weight * input       = product          (the inference step)
//!   product + bias       = output           (the claimed result)
//!   weight * weight      = weight_squared   (parameter binding, part one)
//!   weight_squared + bias = commitment      (parameter binding, part two)
//! ```
//!
//! The first two constraints pin the computation; the last two pin the
//! parameters to a value that is public and was fixed before any inference ran.
//! Satisfying the system requires a single `(weight, bias)` pair that explains
//! the transcript *and* reproduces the commitment, which is exactly the
//! non-substitution property the protocol sells.
//!
//! # Scope, stated plainly
//!
//! This is an affine relation over `Fr`, not a neural network. A production
//! deployment replaces [`InferenceCircuit`] with a quantised arithmetic circuit
//! over the real weight tensor, and replaces the two binding constraints with a
//! Poseidon or Merkle commitment to that tensor. Everything upstream and
//! downstream of the circuit in this repository — the ceremony, the digest
//! derivation, the burn, the BIP-340 commitment, the Nostr transport, the
//! wallet-side check — is independent of that substitution and does not change.
//! The circuit is the component a production deployment swaps; the protocol
//! around it is the contribution.

use ark_bn254::Fr;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};

use crate::error::{Result, TvcError};

/// Number of public inputs the verifier must supply, in allocation order.
pub const PUBLIC_INPUT_ARITY: usize = 3;

/// The committed inference relation.
///
/// Constructed either as a [`blueprint`](InferenceCircuit::blueprint) carrying no
/// assignments, which is what the ceremony synthesises to derive the structural
/// keys, or as a [`witness`](InferenceCircuit::witness) carrying a full
/// assignment, which is what the prover consumes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InferenceCircuit {
    weight: Option<Fr>,
    bias: Option<Fr>,
    input: Option<Fr>,
    output: Option<Fr>,
    commitment: Option<Fr>,
}

impl InferenceCircuit {
    /// Builds the unassigned shape of the relation.
    ///
    /// The trusted setup depends only on the *shape* of the constraint system,
    /// never on any assignment, which is precisely why a verifying key can be
    /// frozen once per model version and reused for every subsequent inference.
    pub const fn blueprint() -> Self {
        Self {
            weight: None,
            bias: None,
            input: None,
            output: None,
            commitment: None,
        }
    }

    /// Builds a fully assigned instance from private parameters and a public input.
    ///
    /// The public `output` and `commitment` are derived here rather than accepted
    /// from the caller so that a prover cannot construct an instance whose public
    /// inputs disagree with its own witness.
    pub fn witness(weight: Fr, bias: Fr, input: Fr) -> Self {
        Self {
            weight: Some(weight),
            bias: Some(bias),
            input: Some(input),
            output: Some(weight * input + bias),
            commitment: Some(weight * weight + bias),
        }
    }

    /// Returns the public inputs in the order the verifier expects them.
    pub fn public_inputs(&self) -> Result<[Fr; PUBLIC_INPUT_ARITY]> {
        Ok([
            self.input.ok_or(TvcError::MissingWitness)?,
            self.output.ok_or(TvcError::MissingWitness)?,
            self.commitment.ok_or(TvcError::MissingWitness)?,
        ])
    }

    /// Returns the public parameter commitment field element, when assigned.
    pub const fn commitment(&self) -> Option<Fr> {
        self.commitment
    }

    /// Returns the claimed public output, when assigned.
    pub const fn output(&self) -> Option<Fr> {
        self.output
    }
}

impl ConstraintSynthesizer<Fr> for InferenceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> core::result::Result<(), SynthesisError> {
        let weight_value = self.weight;
        let bias_value = self.bias;
        let input_value = self.input;
        let output_value = self.output;
        let commitment_value = self.commitment;

        let weight = cs.new_witness_variable(|| weight_value.ok_or(SynthesisError::AssignmentMissing))?;
        let bias = cs.new_witness_variable(|| bias_value.ok_or(SynthesisError::AssignmentMissing))?;

        let input = cs.new_input_variable(|| input_value.ok_or(SynthesisError::AssignmentMissing))?;
        let output = cs.new_input_variable(|| output_value.ok_or(SynthesisError::AssignmentMissing))?;
        let commitment =
            cs.new_input_variable(|| commitment_value.ok_or(SynthesisError::AssignmentMissing))?;

        let product = cs.new_witness_variable(|| {
            let w = weight_value.ok_or(SynthesisError::AssignmentMissing)?;
            let x = input_value.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(w * x)
        })?;
        let weight_squared = cs.new_witness_variable(|| {
            let w = weight_value.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(w * w)
        })?;

        cs.enforce_constraint(lc!() + weight, lc!() + input, lc!() + product)?;
        cs.enforce_constraint(lc!() + product + bias, lc!() + Variable::One, lc!() + output)?;
        cs.enforce_constraint(lc!() + weight, lc!() + weight, lc!() + weight_squared)?;
        cs.enforce_constraint(
            lc!() + weight_squared + bias,
            lc!() + Variable::One,
            lc!() + commitment,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn honest_witness_satisfies_the_relation() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = InferenceCircuit::witness(Fr::from(7u64), Fr::from(3u64), Fr::from(11u64));
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_instance_variables(), PUBLIC_INPUT_ARITY + 1);
    }

    #[test]
    fn substituted_parameters_break_the_binding() {
        let honest = InferenceCircuit::witness(Fr::from(7u64), Fr::from(3u64), Fr::from(11u64));
        let substituted = InferenceCircuit::witness(Fr::from(5u64), Fr::from(3u64), Fr::from(11u64));
        assert_ne!(honest.commitment(), substituted.commitment());
    }

    #[test]
    fn blueprint_exposes_no_assignment() {
        assert!(InferenceCircuit::blueprint().public_inputs().is_err());
    }
}
__W_TVC_FILE_7__

echo "  tvc-core/src/mpc_setup.rs"
cat > 'tvc-core/src/mpc_setup.rs' <<'__W_TVC_FILE_8__'
//! Phase 1 — the Genesis Setup Ceremony.
//!
//! Runs once per model version. Consumes entropy from a set of participants,
//! synthesises the structural keys for [`crate::circuit::InferenceCircuit`],
//! derives the permanent 32-byte verification digest, destroys the entropy, and
//! emits an auditable transcript.
//!
//! # Trust model, stated without inflation
//!
//! **What this implementation provides.** An append-only, hash-chained
//! transcript over N independent entropy contributions. Each contribution is
//! committed under a domain-separated tag and folded into a running digest, so
//! the published transcript cannot be reordered, truncated, or extended after
//! the fact without changing [`CeremonyTranscript::final_digest`]. Every
//! participant can confirm their own contribution is present in the transcript
//! that produced the key. The setup RNG seed is derived from *all* contributions,
//! so no single participant chooses it alone.
//!
//! **What this implementation does not yet provide.** This is not a Phase-2 MPC.
//! The contributions are aggregated into one seed on one machine, which means
//! that at the instant of key extraction the combined entropy exists in a single
//! address space. The honest security claim is therefore *"trust the ceremony
//! operator, with a public transcript that makes participation auditable"* — not
//! the 1-of-N claim a real MPC delivers. Any document describing this code as
//! 1-of-N honest today would be wrong.
//!
//! **The upgrade path.** A true Phase-2 ceremony has each participant apply their
//! contribution to the accumulator on their own machine, publish a proof of
//! correct contribution, and destroy their own share locally; no machine ever
//! holds the combined secret. The interfaces in this module are shaped for that
//! substitution — [`ParticipantContribution`] becomes a contribution-with-proof
//! and [`run_ceremony`] becomes a round-driver — and nothing downstream of
//! [`CeremonyOutput`] changes when it lands. The digest, the burn attestation,
//! the BIP-340 commitment, the Nostr transport, and the wallet-side check are all
//! independent of how the key was produced.
//!
//! # Why the digest can be permanent
//!
//! Groth16's setup depends only on the R1CS *shape*, never on any witness. The
//! shape is fixed by the model architecture, so a verifying key computed once
//! remains valid for every inference that model will ever serve. That is what
//! makes a write-once Nostr commitment sufficient, and why no per-transaction
//! attestation service — or TEE — needs to sit on the runtime path.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::circuit::InferenceCircuit;
use crate::crypto_burn::{BurnAttestation, ToxicWaste};
use crate::digest::{
    chain, tagged_hash, DOMAIN_CEREMONY_SEED, DOMAIN_CONTRIBUTION, DOMAIN_MODEL_BINDING,
    DOMAIN_TRANSCRIPT, DOMAIN_VK_DIGEST,
};
use crate::error::{Result, TvcError};
use crate::hex;

/// Maximum length of a model identifier or version string.
pub const IDENTIFIER_MAX_LEN: usize = 64;

/// Maximum length of the free-form architecture description.
pub const ARCHITECTURE_MAX_LEN: usize = 256;

/// Identifier for the proving system these keys belong to.
///
/// Absorbed into the verifying-key digest so a key from a different backend can
/// never collide with a W-TVC commitment even if its serialisation matched.
pub const SCHEME_TAG: &str = "groth16-bn254";

/// Immutable description of the model version being frozen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelDescriptor {
    /// Stable model identifier, for example `acme-llm-7b`.
    pub model_id: String,
    /// Version string for this frozen release, for example `2026.09`.
    pub version: String,
    /// Human-readable architecture summary recorded in the transcript.
    pub architecture: String,
    /// Declared parameter count, recorded so a downgrade is visible in metadata.
    pub parameter_count: u64,
}

/// Rejects identifiers that cannot survive the protocol's transports intact.
///
/// The permitted alphabet is ASCII alphanumerics plus `-`, `_` and `.`. Three
/// characters are excluded for concrete reasons, not out of caution:
///
/// - **`:`** would make [`ModelDescriptor::address`] ambiguous. The address is
///   `<model_id>:<version>` and becomes the Nostr `d` tag, so a colon inside a
///   component means a consumer splitting on `:` recovers a different
///   `(model, version)` pair than the one that was frozen.
/// - **Newlines** would corrupt the line-delimited descriptor file that
///   `tvc-cli` writes, letting a ceremony be signed under an identity that is
///   not the identity it froze.
/// - **Whitespace and control characters** would let two visually identical
///   identifiers hash differently, or survive a `trim()` as a third value.
///
/// Rejecting at the boundary is cheaper than making every downstream consumer
/// defensive, and a model identifier has no legitimate need for these bytes.
pub fn validate_identifier(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(TvcError::InvalidIdentifier {
            field,
            reason: "must not be empty".to_owned(),
        });
    }
    if value.len() > IDENTIFIER_MAX_LEN {
        return Err(TvcError::InvalidIdentifier {
            field,
            reason: format!("must be at most {IDENTIFIER_MAX_LEN} bytes, got {}", value.len()),
        });
    }
    for character in value.chars() {
        let permitted =
            character.is_ascii_alphanumeric() || character == '-' || character == '_' || character == '.';
        if !permitted {
            return Err(TvcError::InvalidIdentifier {
                field,
                reason: format!(
                    "{character:?} is not permitted; use ASCII letters, digits, '-', '_' or '.'"
                ),
            });
        }
    }
    Ok(())
}

/// Rejects free-form text that would corrupt the descriptor file or transcript.
///
/// Looser than [`validate_identifier`] because this field is prose, but control
/// characters are still refused: they break the line-delimited descriptor file
/// and render unpredictably in a transcript an auditor has to read.
pub fn validate_freeform(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(TvcError::InvalidIdentifier {
            field,
            reason: "must not be empty".to_owned(),
        });
    }
    if value.len() > ARCHITECTURE_MAX_LEN {
        return Err(TvcError::InvalidIdentifier {
            field,
            reason: format!("must be at most {ARCHITECTURE_MAX_LEN} bytes, got {}", value.len()),
        });
    }
    if let Some(character) = value.chars().find(|c| c.is_control()) {
        return Err(TvcError::InvalidIdentifier {
            field,
            reason: format!("control character {character:?} is not permitted"),
        });
    }
    if value.trim() != value {
        return Err(TvcError::InvalidIdentifier {
            field,
            reason: "must not have leading or trailing whitespace".to_owned(),
        });
    }
    Ok(())
}

impl ModelDescriptor {
    /// Builds a descriptor.
    pub fn new(
        model_id: impl Into<String>,
        version: impl Into<String>,
        architecture: impl Into<String>,
        parameter_count: u64,
    ) -> Self {
        Self {
            model_id: model_id.into(),
            version: version.into(),
            architecture: architecture.into(),
            parameter_count,
        }
    }

    /// Confirms every field is safe to transport and to write to disk.
    ///
    /// Called by [`run_ceremony`], so an invalid descriptor can be constructed
    /// but can never be frozen into a verifying key.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidIdentifier`] naming the offending field.
    pub fn validate(&self) -> Result<()> {
        validate_identifier("model_id", &self.model_id)?;
        validate_identifier("version", &self.version)?;
        validate_freeform("architecture", &self.architecture)
    }

    /// Addressable identity of this model version.
    ///
    /// Doubles as the `d` tag of the Nostr commitment event, which is what makes
    /// the commitment addressable as `(kind, pubkey, d)`.
    pub fn address(&self) -> String {
        format!("{}:{}", self.model_id, self.version)
    }

    /// Digest binding every descriptor field into one value.
    pub fn binding_digest(&self) -> [u8; 32] {
        tagged_hash(
            DOMAIN_MODEL_BINDING,
            &[
                self.model_id.as_bytes(),
                self.version.as_bytes(),
                self.architecture.as_bytes(),
                &self.parameter_count.to_be_bytes(),
            ],
        )
    }
}

/// One participant's entropy contribution to the ceremony.
///
/// Holds secret material and erases it on drop, so a contribution that is
/// abandoned on an error path does not linger in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ParticipantContribution {
    participant_id: String,
    entropy: [u8; 32],
}

impl ParticipantContribution {
    /// Registers a participant's 32 bytes of entropy.
    ///
    /// The caller is responsible for sourcing `entropy` from a cryptographically
    /// secure generator; `tvc-cli` uses the operating system CSPRNG.
    pub fn new(participant_id: impl Into<String>, entropy: [u8; 32]) -> Self {
        Self {
            participant_id: participant_id.into(),
            entropy,
        }
    }

    /// Participant identifier as recorded in the transcript.
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    /// Public commitment to this contribution.
    ///
    /// Published in the transcript so a participant can verify their entropy was
    /// included without the entropy itself ever being revealed.
    pub fn commitment(&self) -> [u8; 32] {
        tagged_hash(
            DOMAIN_CONTRIBUTION,
            &[self.participant_id.as_bytes(), &self.entropy],
        )
    }
}

impl core::fmt::Debug for ParticipantContribution {
    /// Renders the identifier and commitment, never the entropy.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParticipantContribution")
            .field("participant_id", &self.participant_id)
            .field("entropy", &"[redacted; 32 bytes]")
            .finish()
    }
}

/// A single audited entry in the ceremony transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContributionRecord {
    /// Zero-based position in the contribution order.
    pub index: u32,
    /// Participant identifier.
    pub participant_id: String,
    /// Public commitment to the participant's entropy.
    pub commitment: [u8; 32],
    /// Running transcript digest after folding this contribution in.
    pub running_digest: [u8; 32],
}

/// The full, publishable record of a ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyTranscript {
    /// Model version this ceremony froze.
    pub model: ModelDescriptor,
    /// Ordered contribution records.
    pub records: Vec<ContributionRecord>,
    /// Terminal value of the hash chain over all contributions.
    pub final_digest: [u8; 32],
}

impl CeremonyTranscript {
    /// Recomputes the hash chain and confirms it reaches [`Self::final_digest`].
    ///
    /// This is the check a third-party auditor runs against a published
    /// transcript. It proves the records were not reordered, removed, or added to
    /// after the ceremony, given only the transcript itself.
    pub fn verify_chain(&self) -> bool {
        let mut running = self.model.binding_digest();
        for (position, record) in self.records.iter().enumerate() {
            if record.index as usize != position {
                return false;
            }
            running = fold(&running, record.index, &record.participant_id, &record.commitment);
            if running != record.running_digest {
                return false;
            }
        }
        running == self.final_digest
    }

    /// Confirms a named participant appears in the transcript.
    pub fn includes(&self, participant_id: &str) -> bool {
        self.records
            .iter()
            .any(|record| record.participant_id == participant_id)
    }
}

/// Everything a ceremony produces.
#[derive(Clone, Debug)]
pub struct CeremonyOutput {
    /// Canonically serialised Groth16 verifying key, compressed.
    pub verifying_key: Vec<u8>,
    /// Canonically serialised Groth16 proving key, compressed.
    pub proving_key: Vec<u8>,
    /// The permanent 32-byte functional verification digest.
    pub vk_digest: [u8; 32],
    /// Auditable transcript of contributions.
    pub transcript: CeremonyTranscript,
    /// Evidence that the setup entropy was destroyed.
    pub burn: BurnAttestation,
}

impl CeremonyOutput {
    /// Lowercase hex rendering of [`Self::vk_digest`].
    pub fn vk_digest_hex(&self) -> String {
        hex::encode(&self.vk_digest)
    }

    /// Lowercase hex rendering of the transcript's final digest.
    pub fn transcript_digest_hex(&self) -> String {
        hex::encode(&self.transcript.final_digest)
    }
}

/// Derives the permanent verification digest from a serialised verifying key.
///
/// Deliberately a function of the key bytes and the scheme tag alone, with no
/// model metadata mixed in. A wallet that has fetched a commitment from a relay
/// must be able to recompute this digest from the verifying key it was handed and
/// nothing else; binding model identity is the job of the signed commitment in
/// [`crate::proof_verifier`], not of the digest.
pub fn derive_vk_digest(verifying_key: &[u8]) -> [u8; 32] {
    tagged_hash(DOMAIN_VK_DIGEST, &[SCHEME_TAG.as_bytes(), verifying_key])
}

/// Executes a ceremony end to end.
///
/// Consumes `contributions` by value so that every participant's entropy is
/// erased when this function returns, on both the success and the error path.
///
/// # Errors
///
/// Returns [`TvcError::EmptyCeremony`] with no contributions, and
/// [`TvcError::DuplicateParticipant`] if two contributions share an identifier,
/// which would make the transcript ambiguous about who contributed what.
pub fn run_ceremony(
    model: ModelDescriptor,
    contributions: Vec<ParticipantContribution>,
) -> Result<CeremonyOutput> {
    model.validate()?;

    if contributions.is_empty() {
        return Err(TvcError::EmptyCeremony);
    }
    for (position, contribution) in contributions.iter().enumerate() {
        if contributions[..position]
            .iter()
            .any(|earlier| earlier.participant_id == contribution.participant_id)
        {
            return Err(TvcError::DuplicateParticipant(
                contribution.participant_id.clone(),
            ));
        }
    }

    let mut running = model.binding_digest();
    let mut records = Vec::with_capacity(contributions.len());
    let mut entropy_pool = Vec::with_capacity(contributions.len());

    for (position, contribution) in contributions.iter().enumerate() {
        let index = position as u32;
        let commitment = contribution.commitment();
        running = fold(&running, index, contribution.participant_id(), &commitment);
        records.push(ContributionRecord {
            index,
            participant_id: contribution.participant_id().to_owned(),
            commitment,
            running_digest: running,
        });
        entropy_pool.push(contribution.entropy);
    }

    let transcript = CeremonyTranscript {
        model: model.clone(),
        records,
        final_digest: running,
    };

    let mut seed_parts: Vec<&[u8]> = Vec::with_capacity(entropy_pool.len() + 2);
    let model_binding = model.binding_digest();
    seed_parts.push(&model_binding);
    seed_parts.push(&transcript.final_digest);
    for entropy in &entropy_pool {
        seed_parts.push(entropy);
    }
    let ceremony_seed = tagged_hash(DOMAIN_CEREMONY_SEED, &seed_parts);
    drop(seed_parts);

    let waste = ToxicWaste::new(ceremony_seed, entropy_pool);

    let mut rng = StdRng::from_seed(*waste.ceremony_seed());
    let (proving_key, verifying_key) =
        Groth16::<Bn254>::circuit_specific_setup(InferenceCircuit::blueprint(), &mut rng)?;

    let mut verifying_key_bytes = Vec::new();
    verifying_key.serialize_compressed(&mut verifying_key_bytes)?;
    let mut proving_key_bytes = Vec::new();
    proving_key.serialize_compressed(&mut proving_key_bytes)?;

    let vk_digest = derive_vk_digest(&verifying_key_bytes);
    let burn = waste.burn(transcript.final_digest, vk_digest);

    Ok(CeremonyOutput {
        verifying_key: verifying_key_bytes,
        proving_key: proving_key_bytes,
        vk_digest,
        transcript,
        burn,
    })
}

/// Field element helper for callers assembling witnesses from integers.
pub fn field_from_u64(value: u64) -> Fr {
    Fr::from(value)
}

fn fold(previous: &[u8; 32], index: u32, participant_id: &str, commitment: &[u8; 32]) -> [u8; 32] {
    let mut element = Vec::with_capacity(4 + participant_id.len() + 32);
    element.extend_from_slice(&index.to_be_bytes());
    element.extend_from_slice(participant_id.as_bytes());
    element.extend_from_slice(commitment);
    chain(DOMAIN_TRANSCRIPT, previous, &element)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> ModelDescriptor {
        ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 7_000_000_000)
    }

    fn contributions() -> Vec<ParticipantContribution> {
        vec![
            ParticipantContribution::new("bitshala", [1u8; 32]),
            ParticipantContribution::new("acme-labs", [2u8; 32]),
            ParticipantContribution::new("independent-auditor", [3u8; 32]),
        ]
    }

    #[test]
    fn ceremony_produces_a_verifiable_transcript() {
        let output = run_ceremony(model(), contributions()).unwrap();
        assert!(output.transcript.verify_chain());
        assert_eq!(output.transcript.records.len(), 3);
        assert!(output.transcript.includes("bitshala"));
        assert_eq!(output.vk_digest_hex().len(), 64);
    }

    #[test]
    fn digest_is_a_pure_function_of_the_key() {
        let output = run_ceremony(model(), contributions()).unwrap();
        assert_eq!(derive_vk_digest(&output.verifying_key), output.vk_digest);
    }

    #[test]
    fn ceremony_is_deterministic_in_its_contributions() {
        let first = run_ceremony(model(), contributions()).unwrap();
        let second = run_ceremony(model(), contributions()).unwrap();
        assert_eq!(first.vk_digest, second.vk_digest);
        assert_eq!(first.transcript.final_digest, second.transcript.final_digest);
    }

    #[test]
    fn different_entropy_yields_a_different_key() {
        let baseline = run_ceremony(model(), contributions()).unwrap();
        let altered = run_ceremony(
            model(),
            vec![
                ParticipantContribution::new("bitshala", [9u8; 32]),
                ParticipantContribution::new("acme-labs", [2u8; 32]),
                ParticipantContribution::new("independent-auditor", [3u8; 32]),
            ],
        )
        .unwrap();
        assert_ne!(baseline.vk_digest, altered.vk_digest);
    }

    #[test]
    fn different_model_version_yields_a_different_key() {
        let baseline = run_ceremony(model(), contributions()).unwrap();
        let downgraded = run_ceremony(
            ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 1_500_000_000),
            contributions(),
        )
        .unwrap();
        assert_ne!(baseline.vk_digest, downgraded.vk_digest);
    }

    #[test]
    fn empty_and_duplicate_ceremonies_are_rejected() {
        assert_eq!(run_ceremony(model(), vec![]).unwrap_err(), TvcError::EmptyCeremony);
        let duplicated = vec![
            ParticipantContribution::new("same", [1u8; 32]),
            ParticipantContribution::new("same", [2u8; 32]),
        ];
        assert!(matches!(
            run_ceremony(model(), duplicated).unwrap_err(),
            TvcError::DuplicateParticipant(_)
        ));
    }

    #[test]
    fn reordered_transcript_fails_the_chain_check() {
        let output = run_ceremony(model(), contributions()).unwrap();
        let mut tampered = output.transcript.clone();
        tampered.records.swap(0, 1);
        assert!(!tampered.verify_chain());
    }

    #[test]
    fn truncated_transcript_fails_the_chain_check() {
        let output = run_ceremony(model(), contributions()).unwrap();
        let mut tampered = output.transcript.clone();
        tampered.records.pop();
        assert!(!tampered.verify_chain());
    }

    #[test]
    fn burn_attestation_matches_the_ceremony_it_describes() {
        let output = run_ceremony(model(), contributions()).unwrap();
        assert_eq!(output.burn.contributions, 3);
        assert_eq!(output.burn.vk_digest, output.vk_digest);
        assert_eq!(output.burn.transcript_digest, output.transcript.final_digest);
    }

    #[test]
    fn colon_in_an_identifier_is_rejected() {
        let ambiguous = ModelDescriptor::new("acme:llm", "2026.09", "affine", 1);
        assert!(matches!(
            ambiguous.validate().unwrap_err(),
            TvcError::InvalidIdentifier { field: "model_id", .. }
        ));
        assert!(matches!(
            run_ceremony(ambiguous, contributions()).unwrap_err(),
            TvcError::InvalidIdentifier { .. }
        ));
    }

    #[test]
    fn newline_in_an_identifier_is_rejected() {
        let corrupting = ModelDescriptor::new("bad\nid", "1", "affine", 1);
        assert!(matches!(
            corrupting.validate().unwrap_err(),
            TvcError::InvalidIdentifier { field: "model_id", .. }
        ));
    }

    #[test]
    fn whitespace_and_control_characters_are_rejected() {
        for bad in ["has space", " lead", "trail ", "tab\there", "null\0byte"] {
            assert!(
                validate_identifier("model_id", bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn empty_and_overlong_identifiers_are_rejected() {
        assert!(validate_identifier("version", "").is_err());
        assert!(validate_identifier("version", &"v".repeat(IDENTIFIER_MAX_LEN + 1)).is_err());
        assert!(validate_identifier("version", &"v".repeat(IDENTIFIER_MAX_LEN)).is_ok());
    }

    #[test]
    fn realistic_identifiers_are_accepted() {
        for good in ["acme-llm-7b", "2026.09", "model_v2", "a", "gpt-4.1-turbo"] {
            assert!(validate_identifier("model_id", good).is_ok(), "expected {good:?} to pass");
        }
    }

    #[test]
    fn architecture_rejects_control_characters_but_allows_prose() {
        assert!(validate_freeform("architecture", "affine committed inference").is_ok());
        assert!(validate_freeform("architecture", "two\nlines").is_err());
        assert!(validate_freeform("architecture", " padded ").is_err());
    }

    #[test]
    fn binding_digest_detects_identity_drift() {
        let frozen = ModelDescriptor::new("acme-llm-7b", "2026.09", "affine", 7_000_000_000);
        let drifted = ModelDescriptor::new("acme-llm-7b", "2026.10", "affine", 7_000_000_000);
        assert_ne!(frozen.binding_digest(), drifted.binding_digest());
    }

    #[test]
    fn model_address_is_the_nostr_d_tag() {
        assert_eq!(model().address(), "acme-llm-7b:2026.09");
    }
}
__W_TVC_FILE_8__

echo "  tvc-core/src/crypto_burn.rs"
cat > 'tvc-core/src/crypto_burn.rs' <<'__W_TVC_FILE_9__'
//! Destruction of setup entropy — the "toxic waste" — after key extraction.
//!
//! # Why the waste is dangerous
//!
//! Groth16's structural keys are derived from secret field elements sampled
//! during setup. Anyone holding those elements can forge a proof for a statement
//! that is false while still passing the verifier's pairing check. In the W-TVC
//! threat model that is the whole game: a lab that retains its setup entropy can
//! serve a cheaper model and still mint proofs that satisfy the frozen verifying
//! key, and no downstream wallet could tell. The commitment is only worth what
//! the destruction of the entropy is worth.
//!
//! # How destruction is implemented
//!
//! [`ToxicWaste`] owns every secret byte the ceremony touched at this layer: the
//! per-participant entropy and the aggregated ceremony seed derived from it. It
//! derives [`Zeroize`] and [`ZeroizeOnDrop`], which gives two independent paths
//! to erasure:
//!
//! 1. **Explicit.** [`ToxicWaste::burn`] consumes the value by move, overwrites
//!    the secret buffers, and returns a [`BurnAttestation`]. This is the path the
//!    ceremony actually takes, and it is the one that produces auditable
//!    evidence. Taking `self` by value makes the burn a type-level event: the
//!    handle is gone afterwards, so no later code path can read the entropy,
//!    because no later code path has anything to read it from.
//! 2. **Implicit.** If a ceremony aborts early and the value is simply dropped,
//!    `ZeroizeOnDrop` runs the same overwrite in `Drop`, before the allocator
//!    reclaims the pages. An error path that forgets to burn still erases.
//!
//! The overwrite itself is `core::ptr::write_volatile`. A plain `*buf = [0u8;32]`
//! on a value that is never read again is dead-store eliminated by LLVM — the
//! compiler is entitled to delete a write whose result is unobservable, which is
//! how naive zeroization silently becomes a no-op under `--release`. A volatile
//! write is defined as an observable side effect, so it survives optimisation.
//! `zeroize` additionally zeroes a `Vec`'s **entire capacity**, not merely its
//! initialised prefix, so residue past `len` is covered.
//!
//! # What this does not protect against
//!
//! Stating the limits precisely, because a ceremony that oversells its hygiene is
//! worse than one that documents it:
//!
//! - **Prior reallocations.** If a `Vec` holding secrets grew, the old heap
//!   buffer was already copied and freed, and this type cannot reach it. Secret
//!   buffers here are allocated once at their final size to avoid the growth path.
//! - **Register and stack spills.** Field elements pass through registers and
//!   stack slots that no destructor owns. `arkworks` copies `Fr` values freely
//!   inside its setup routines; those temporaries are outside this type's reach.
//!   This is the strongest reason a real deployment runs the ceremony on an
//!   ephemeral, air-gapped machine that is destroyed afterwards.
//! - **Swap, hibernation, and core dumps.** Pages can reach persistent storage
//!   before any overwrite runs. Operators should disable swap and core dumps for
//!   the ceremony process; `mlock` is a reasonable hardening step and is not
//!   attempted here because it needs privileges this library should not assume.
//! - **Panic paths under `panic = "abort"`.** The release profile aborts instead
//!   of unwinding, and an aborting process does not run destructors. The implicit
//!   drop path therefore covers ordinary early returns, not panics. Disabling
//!   core dumps is what covers the panic case.
//!
//! # What a real ceremony adds
//!
//! Honest scope: burning entropy on one machine reduces to trusting whoever ran
//! that machine. A production W-TVC ceremony runs a Phase-2 MPC in which each
//! participant applies their contribution to the accumulator, publishes a proof
//! of correct contribution, and destroys their own share independently. The
//! security claim then weakens from "trust the operator" to "trust that at least
//! one of N participants was honest". See [`crate::mpc_setup`] for where that
//! upgrade lands in this codebase.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::digest::{tagged_hash, DOMAIN_BURN_ATTESTATION};
use crate::hex;

/// Secret material produced by a ceremony that must never outlive key extraction.
///
/// Constructed by [`crate::mpc_setup::run_ceremony`] and normally consumed by
/// [`ToxicWaste::burn`] within the same function body.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ToxicWaste {
    ceremony_seed: [u8; 32],
    participant_entropy: Vec<[u8; 32]>,
}

impl ToxicWaste {
    /// Takes ownership of the ceremony's secret material.
    ///
    /// `participant_entropy` is collected into an exactly-sized allocation so the
    /// buffer is never grown, which removes the reallocation-residue path
    /// described in the module documentation.
    pub fn new(ceremony_seed: [u8; 32], participant_entropy: Vec<[u8; 32]>) -> Self {
        let mut exact = Vec::with_capacity(participant_entropy.len());
        exact.extend_from_slice(&participant_entropy);
        Self {
            ceremony_seed,
            participant_entropy: exact,
        }
    }

    /// Borrows the ceremony seed for the duration of key extraction.
    ///
    /// Deliberately a borrow rather than a copy: handing out an owned `[u8; 32]`
    /// would create a second copy with no destructor, defeating the entire
    /// module. The borrow cannot outlive the `ToxicWaste` that will erase it.
    pub const fn ceremony_seed(&self) -> &[u8; 32] {
        &self.ceremony_seed
    }

    /// Number of independent entropy contributions held.
    pub fn contribution_count(&self) -> usize {
        self.participant_entropy.len()
    }

    /// Total secret bytes under management.
    pub fn secret_len(&self) -> usize {
        self.ceremony_seed.len() + self.participant_entropy.len() * 32
    }

    /// Overwrites every secret byte in place without consuming the value.
    ///
    /// Provided for callers that must erase at a point where ownership cannot be
    /// surrendered. [`ToxicWaste::burn`] is preferable wherever ownership is
    /// available, because it also removes the handle.
    pub fn zeroize_now(&mut self) {
        self.zeroize();
    }

    /// Destroys the setup entropy and returns evidence that it happened.
    ///
    /// Consumes `self`; the `Drop` implementation installed by `ZeroizeOnDrop`
    /// performs the volatile overwrite as the value goes out of scope at the end
    /// of this call. The returned [`BurnAttestation`] contains no secret material
    /// and is safe to publish alongside the ceremony transcript.
    pub fn burn(self, transcript_digest: [u8; 32], vk_digest: [u8; 32]) -> BurnAttestation {
        let burned_bytes = self.secret_len();
        let contributions = self.contribution_count();

        let attestation_digest = tagged_hash(
            DOMAIN_BURN_ATTESTATION,
            &[
                &transcript_digest,
                &vk_digest,
                &(contributions as u64).to_be_bytes(),
                &(burned_bytes as u64).to_be_bytes(),
            ],
        );

        BurnAttestation {
            transcript_digest,
            vk_digest,
            contributions,
            burned_bytes,
            attestation_digest,
        }
    }
}

impl core::fmt::Debug for ToxicWaste {
    /// Renders shape only.
    ///
    /// A derived `Debug` would print the entropy into logs, tracing spans, and
    /// panic messages, which is a far more probable leak than any memory-residue
    /// attack this module defends against.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ToxicWaste")
            .field("ceremony_seed", &"[redacted; 32 bytes]")
            .field("contributions", &self.participant_entropy.len())
            .finish()
    }
}

/// Publishable, secret-free evidence that setup entropy was destroyed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BurnAttestation {
    /// Digest of the ceremony transcript whose entropy was destroyed.
    pub transcript_digest: [u8; 32],
    /// Digest of the verifying key the destroyed entropy produced.
    pub vk_digest: [u8; 32],
    /// Number of independent contributions destroyed.
    pub contributions: usize,
    /// Count of secret bytes overwritten.
    pub burned_bytes: usize,
    /// Tagged hash binding the fields above into a single citable value.
    pub attestation_digest: [u8; 32],
}

impl BurnAttestation {
    /// Lowercase hex rendering of [`Self::attestation_digest`].
    pub fn attestation_hex(&self) -> String {
        hex::encode(&self.attestation_digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_now_clears_every_secret_byte() {
        let mut waste = ToxicWaste::new([0xab; 32], vec![[0xcd; 32], [0xef; 32]]);
        assert_ne!(waste.ceremony_seed, [0u8; 32]);
        assert_eq!(waste.contribution_count(), 2);

        waste.zeroize_now();

        assert_eq!(waste.ceremony_seed, [0u8; 32]);
        assert!(waste.participant_entropy.is_empty());
    }

    #[test]
    fn burn_reports_the_volume_it_destroyed() {
        let waste = ToxicWaste::new([7u8; 32], vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        let attestation = waste.burn([9u8; 32], [4u8; 32]);
        assert_eq!(attestation.contributions, 3);
        assert_eq!(attestation.burned_bytes, 32 + 3 * 32);
        assert_eq!(attestation.attestation_hex().len(), 64);
    }

    #[test]
    fn attestation_digest_binds_its_inputs() {
        let a = ToxicWaste::new([7u8; 32], vec![[1u8; 32]]).burn([9u8; 32], [4u8; 32]);
        let b = ToxicWaste::new([7u8; 32], vec![[1u8; 32]]).burn([9u8; 32], [5u8; 32]);
        assert_ne!(a.attestation_digest, b.attestation_digest);
    }

    #[test]
    fn debug_never_renders_entropy() {
        let waste = ToxicWaste::new([0x41; 32], vec![[0x42; 32]]);
        let rendered = format!("{waste:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("41"));
    }
}
__W_TVC_FILE_9__

echo "  tvc-core/src/proof_verifier.rs"
cat > 'tvc-core/src/proof_verifier.rs' <<'__W_TVC_FILE_10__'
//! Phase 2 — runtime verification, and the signed commitment that anchors it.
//!
//! # The check that does the work
//!
//! [`verify_inference`] performs two tests in a deliberate order:
//!
//! 1. **Commitment check.** Recompute the digest of the verifying key handed over
//!    at runtime and compare it to the digest fetched from a Nostr relay. A
//!    mismatch aborts immediately with [`TvcError::CommitmentMismatch`].
//! 2. **Pairing check.** Only then run Groth16 verification of the proof against
//!    that key and the claimed public inputs.
//!
//! The ordering is the security argument, not an optimisation. A provider that
//! substitutes a cheaper model can still produce proofs that are *internally
//! valid* — correct proofs about the wrong circuit. Running the pairing check
//! first and the commitment check second, or treating the two as interchangeable
//! booleans, would accept exactly the attack this protocol exists to stop. The
//! only key a wallet will verify against is the key the consortium froze.
//!
//! # Why the anchor is BIP-340
//!
//! [`ParameterCommitment`] is signed with a secp256k1 Schnorr signature over a
//! tagged sighash. That is the same curve and signature scheme as a Nostr event
//! signature, so the consortium's ceremony identity and its Nostr publishing
//! identity are one key. A wallet that trusts `npub1...` to publish commitments
//! is trusting a single well-defined public key, with no certificate chain, no
//! registry, and no attestation service on the runtime path.
//!
//! The digest itself is deliberately *not* bound to model metadata (see
//! [`crate::mpc_setup::derive_vk_digest`]); the signature is what binds a key to
//! a claimed model identity. Separating the two means a wallet can verify the key
//! it holds is the key that was committed using only arithmetic, and separately
//! decide whether it trusts the signer's claim about which model that key is.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use secp256k1::{schnorr, Keypair, SecretKey, XOnlyPublicKey};

use crate::circuit::InferenceCircuit;
use crate::digest::{tagged_hash, DOMAIN_COMMITMENT_SIGHASH};
use crate::error::{Result, TvcError};
use crate::hex;
use crate::mpc_setup::{derive_vk_digest, SCHEME_TAG};

/// A consortium's published claim about one frozen model version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterCommitment {
    /// Stable model identifier.
    pub model_id: String,
    /// Frozen version string.
    pub version: String,
    /// Proving system tag, always [`SCHEME_TAG`] for this release.
    pub scheme: String,
    /// The permanent 32-byte functional verification digest.
    pub vk_digest: [u8; 32],
    /// Final digest of the ceremony transcript that produced the key.
    pub transcript_digest: [u8; 32],
    /// Digest of the toxic-waste burn attestation.
    pub burn_digest: [u8; 32],
}

impl ParameterCommitment {
    /// Assembles a commitment from ceremony output.
    pub fn new(
        model_id: impl Into<String>,
        version: impl Into<String>,
        vk_digest: [u8; 32],
        transcript_digest: [u8; 32],
        burn_digest: [u8; 32],
    ) -> Self {
        Self {
            model_id: model_id.into(),
            version: version.into(),
            scheme: SCHEME_TAG.to_owned(),
            vk_digest,
            transcript_digest,
            burn_digest,
        }
    }

    /// Addressable identity, used as the Nostr `d` tag.
    pub fn address(&self) -> String {
        format!("{}:{}", self.model_id, self.version)
    }

    /// The 32-byte message signed by the consortium key.
    ///
    /// Covers every field, so a relay or a malicious republisher cannot pair a
    /// genuine signature with an altered model identity or a different digest.
    pub fn sighash(&self) -> [u8; 32] {
        tagged_hash(
            DOMAIN_COMMITMENT_SIGHASH,
            &[
                self.model_id.as_bytes(),
                self.version.as_bytes(),
                self.scheme.as_bytes(),
                &self.vk_digest,
                &self.transcript_digest,
                &self.burn_digest,
            ],
        )
    }

    /// Signs this commitment with a BIP-340 Schnorr signature.
    ///
    /// `aux_rand` is supplied by the caller rather than sampled internally so the
    /// signing path has no hidden entropy source and is reproducible under test.
    /// Production callers must pass fresh randomness from the operating system.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::Signature`] if `secret_key` is not a valid scalar.
    pub fn sign(&self, secret_key: &[u8; 32], aux_rand: &[u8; 32]) -> Result<SignedCommitment> {
        let secret = SecretKey::from_secret_bytes(*secret_key)?;
        let keypair = Keypair::from_secret_key(&secret);
        let (signer, _parity) = keypair.x_only_public_key();
        let sighash = self.sighash();
        let signature = schnorr::sign_with_aux_rand(&sighash, &keypair, aux_rand);

        Ok(SignedCommitment {
            commitment: self.clone(),
            signature: *signature.as_ref(),
            signer: signer.to_byte_array(),
        })
    }

    /// Lowercase hex rendering of [`Self::vk_digest`].
    pub fn vk_digest_hex(&self) -> String {
        hex::encode(&self.vk_digest)
    }
}

/// A [`ParameterCommitment`] carrying its BIP-340 signature and signer key.
///
/// This is the payload that travels in a kind `30200` Nostr event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCommitment {
    /// The signed claim.
    pub commitment: ParameterCommitment,
    /// 64-byte BIP-340 Schnorr signature over [`ParameterCommitment::sighash`].
    pub signature: [u8; 64],
    /// 32-byte x-only public key of the consortium, equal to the Nostr pubkey.
    pub signer: [u8; 32],
}

impl SignedCommitment {
    /// Verifies the signature against the embedded signer key.
    ///
    /// Establishes only that *this* key signed *this* claim. Deciding whether the
    /// key is the one a wallet should trust is policy, handled by
    /// [`Self::verify_signed_by`].
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::CommitmentUnsigned`] when verification fails.
    pub fn verify(&self) -> Result<()> {
        let pubkey = XOnlyPublicKey::from_byte_array(self.signer)?;
        let signature = schnorr::Signature::from_byte_array(self.signature);
        signature
            .verify(&self.commitment.sighash(), &pubkey)
            .map_err(|_| TvcError::CommitmentUnsigned)
    }

    /// Verifies the signature and pins it to an expected consortium key.
    ///
    /// This is what a wallet calls. Accepting any valid signature would let an
    /// arbitrary relay-published key vouch for a model, which is no trust anchor
    /// at all; the wallet must already know whose commitments it honours.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::CommitmentUnsigned`] if the signer differs from
    /// `expected_signer` or the signature does not verify.
    pub fn verify_signed_by(&self, expected_signer: &[u8; 32]) -> Result<()> {
        if &self.signer != expected_signer {
            return Err(TvcError::CommitmentUnsigned);
        }
        self.verify()
    }

    /// Lowercase hex rendering of the signer's x-only public key.
    pub fn signer_hex(&self) -> String {
        hex::encode(&self.signer)
    }

    /// Lowercase hex rendering of the signature.
    pub fn signature_hex(&self) -> String {
        hex::encode(&self.signature)
    }
}

/// A runtime inference proof together with its public inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceProof {
    /// Canonically serialised compressed Groth16 proof.
    pub proof: Vec<u8>,
    /// Public inputs in circuit allocation order.
    pub public_inputs: Vec<Fr>,
}

impl InferenceProof {
    /// Lowercase hex rendering of the serialised proof.
    pub fn proof_hex(&self) -> String {
        hex::encode(&self.proof)
    }

    /// Serialises the public inputs to hex strings for transport.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::Codec`] if a field element fails to serialise.
    pub fn public_inputs_hex(&self) -> Result<Vec<String>> {
        self.public_inputs
            .iter()
            .map(|value| {
                let mut bytes = Vec::new();
                value.serialize_compressed(&mut bytes)?;
                Ok(hex::encode(&bytes))
            })
            .collect()
    }

    /// Parses public inputs previously rendered by [`Self::public_inputs_hex`].
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::MalformedHex`] or [`TvcError::Codec`] on malformed input.
    pub fn public_inputs_from_hex(values: &[String]) -> Result<Vec<Fr>> {
        values
            .iter()
            .map(|text| {
                let bytes = hex::decode(text)?;
                Fr::deserialize_compressed(bytes.as_slice()).map_err(TvcError::from)
            })
            .collect()
    }
}

/// Outcome of a successful runtime verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationReport {
    /// Digest recomputed from the verifying key presented at runtime.
    pub observed_vk_digest: [u8; 32],
    /// True once the recomputed digest matched the published commitment.
    pub commitment_matched: bool,
    /// True once the Groth16 pairing check accepted the proof.
    pub proof_valid: bool,
}

impl VerificationReport {
    /// True only when both the commitment and the proof checks passed.
    pub const fn accepted(&self) -> bool {
        self.commitment_matched && self.proof_valid
    }
}

/// Generates a proof that committed parameters produced a claimed output.
///
/// `proof_seed` must be fresh for every proof. Groth16 proofs are randomised, and
/// reusing the same randomness across two proofs from the same proving key
/// degrades the zero-knowledge property the protocol relies on to keep model
/// weights private.
///
/// # Errors
///
/// Returns [`TvcError::Codec`] if `proving_key` is malformed, or
/// [`TvcError::Synthesis`] if constraint generation fails.
pub fn prove_inference(
    proving_key: &[u8],
    weight: Fr,
    bias: Fr,
    input: Fr,
    proof_seed: [u8; 32],
) -> Result<InferenceProof> {
    let key = ProvingKey::<Bn254>::deserialize_compressed(proving_key)?;
    let circuit = InferenceCircuit::witness(weight, bias, input);
    let public_inputs = circuit.public_inputs()?.to_vec();

    let mut rng = StdRng::from_seed(proof_seed);
    let proof = Groth16::<Bn254>::prove(&key, circuit, &mut rng)?;

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;

    Ok(InferenceProof {
        proof: proof_bytes,
        public_inputs,
    })
}

/// Verifies an inference proof against a published parameter commitment.
///
/// Checks the verifying key against `committed_vk_digest` *before* touching the
/// proof. See the module documentation for why that order is load-bearing.
///
/// # Errors
///
/// - [`TvcError::CommitmentMismatch`] if the runtime key is not the committed key.
/// - [`TvcError::Codec`] if the key or proof is malformed.
/// - [`TvcError::ProofRejected`] if the pairing check fails.
pub fn verify_inference(
    verifying_key: &[u8],
    committed_vk_digest: &[u8; 32],
    public_inputs: &[Fr],
    proof: &[u8],
) -> Result<VerificationReport> {
    let observed_vk_digest = derive_vk_digest(verifying_key);
    if &observed_vk_digest != committed_vk_digest {
        return Err(TvcError::CommitmentMismatch {
            expected: hex::encode(committed_vk_digest),
            observed: hex::encode(&observed_vk_digest),
        });
    }

    let key = VerifyingKey::<Bn254>::deserialize_compressed(verifying_key)?;
    let parsed_proof = Proof::<Bn254>::deserialize_compressed(proof)?;

    let proof_valid = Groth16::<Bn254>::verify(&key, public_inputs, &parsed_proof)?;
    if !proof_valid {
        return Err(TvcError::ProofRejected);
    }

    Ok(VerificationReport {
        observed_vk_digest,
        commitment_matched: true,
        proof_valid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc_setup::{run_ceremony, ModelDescriptor, ParticipantContribution};

    fn ceremony() -> crate::mpc_setup::CeremonyOutput {
        run_ceremony(
            ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 7_000_000_000),
            vec![
                ParticipantContribution::new("bitshala", [1u8; 32]),
                ParticipantContribution::new("acme-labs", [2u8; 32]),
            ],
        )
        .unwrap()
    }

    #[test]
    fn honest_proof_verifies_against_the_committed_digest() {
        let setup = ceremony();
        let proof = prove_inference(
            &setup.proving_key,
            Fr::from(7u64),
            Fr::from(3u64),
            Fr::from(11u64),
            [42u8; 32],
        )
        .unwrap();

        let report = verify_inference(
            &setup.verifying_key,
            &setup.vk_digest,
            &proof.public_inputs,
            &proof.proof,
        )
        .unwrap();

        assert!(report.accepted());
    }

    #[test]
    fn substituted_model_is_rejected_on_the_commitment_not_the_proof() {
        let committed = ceremony();
        let substitute = run_ceremony(
            ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 7_000_000_000),
            vec![ParticipantContribution::new("rogue-operator", [9u8; 32])],
        )
        .unwrap();

        let proof = prove_inference(
            &substitute.proving_key,
            Fr::from(7u64),
            Fr::from(3u64),
            Fr::from(11u64),
            [42u8; 32],
        )
        .unwrap();

        let verified_against_substitute = verify_inference(
            &substitute.verifying_key,
            &substitute.vk_digest,
            &proof.public_inputs,
            &proof.proof,
        )
        .unwrap();
        assert!(verified_against_substitute.accepted());

        let error = verify_inference(
            &substitute.verifying_key,
            &committed.vk_digest,
            &proof.public_inputs,
            &proof.proof,
        )
        .unwrap_err();
        assert!(matches!(error, TvcError::CommitmentMismatch { .. }));
    }

    #[test]
    fn tampered_public_output_is_rejected_by_the_pairing_check() {
        let setup = ceremony();
        let proof = prove_inference(
            &setup.proving_key,
            Fr::from(7u64),
            Fr::from(3u64),
            Fr::from(11u64),
            [42u8; 32],
        )
        .unwrap();

        let mut forged = proof.public_inputs.clone();
        forged[1] += Fr::from(1u64);

        let error =
            verify_inference(&setup.verifying_key, &setup.vk_digest, &forged, &proof.proof).unwrap_err();
        assert_eq!(error, TvcError::ProofRejected);
    }

    #[test]
    fn public_inputs_survive_a_hex_roundtrip() {
        let setup = ceremony();
        let proof = prove_inference(
            &setup.proving_key,
            Fr::from(7u64),
            Fr::from(3u64),
            Fr::from(11u64),
            [42u8; 32],
        )
        .unwrap();
        let encoded = proof.public_inputs_hex().unwrap();
        let decoded = InferenceProof::public_inputs_from_hex(&encoded).unwrap();
        assert_eq!(decoded, proof.public_inputs);
    }

    #[test]
    fn commitment_signature_roundtrips() {
        let setup = ceremony();
        let commitment = ParameterCommitment::new(
            "acme-llm-7b",
            "2026.09",
            setup.vk_digest,
            setup.transcript.final_digest,
            setup.burn.attestation_digest,
        );
        let signed = commitment.sign(&[0x11; 32], &[0x22; 32]).unwrap();

        assert!(signed.verify().is_ok());
        assert!(signed.verify_signed_by(&signed.signer).is_ok());
        assert_eq!(signed.signer_hex().len(), 64);
        assert_eq!(signed.signature_hex().len(), 128);
    }

    #[test]
    fn altered_commitment_breaks_its_signature() {
        let setup = ceremony();
        let commitment = ParameterCommitment::new(
            "acme-llm-7b",
            "2026.09",
            setup.vk_digest,
            setup.transcript.final_digest,
            setup.burn.attestation_digest,
        );
        let mut signed = commitment.sign(&[0x11; 32], &[0x22; 32]).unwrap();
        signed.commitment.version = "2026.10".to_owned();

        assert_eq!(signed.verify().unwrap_err(), TvcError::CommitmentUnsigned);
    }

    #[test]
    fn commitment_from_an_untrusted_key_is_rejected() {
        let setup = ceremony();
        let commitment = ParameterCommitment::new(
            "acme-llm-7b",
            "2026.09",
            setup.vk_digest,
            setup.transcript.final_digest,
            setup.burn.attestation_digest,
        );
        let signed = commitment.sign(&[0x11; 32], &[0x22; 32]).unwrap();
        let unrelated = [0x33; 32];

        assert_eq!(
            signed.verify_signed_by(&unrelated).unwrap_err(),
            TvcError::CommitmentUnsigned
        );
    }
}
__W_TVC_FILE_10__

echo "  tvc-core/src/digest.rs"
cat > 'tvc-core/src/digest.rs' <<'__W_TVC_FILE_11__'
//! Domain-separated hashing for every commitment the protocol publishes.
//!
//! # Tagged hashing
//!
//! All digests use the BIP-340 tagged-hash construction:
//!
//! ```text
//!   tagged_hash(tag, m) = SHA256( SHA256(tag) || SHA256(tag) || m )
//! ```
//!
//! The doubled tag hash fills a full SHA-256 block, so the midstate after the
//! prefix is fixed per tag. The security property that matters here is domain
//! separation: a verifying-key digest and a ceremony-transcript digest are both
//! 32 bytes over caller-controlled input, and without distinct tags an adversary
//! could try to present one as the other. Reusing Bitcoin's own construction,
//! rather than inventing a scheme, keeps W-TVC digests auditable by anyone who
//! already knows BIP-340.
//!
//! # Length prefixing
//!
//! Each message part is prefixed with its length as a big-endian `u64` before
//! being absorbed. Plain concatenation is ambiguous — `("ab", "c")` and
//! `("a", "bc")` hash identically — which would let a participant identifier
//! absorb bytes from an adjacent field and forge a transcript entry that appears
//! to commit to something it does not. Length prefixing makes the encoding
//! injective, so one digest corresponds to exactly one tuple of inputs.

use bitcoin_hashes::{sha256, HashEngine};

/// Tag for the aggregated ceremony RNG seed.
pub const DOMAIN_CEREMONY_SEED: &str = "W-TVC/v1/ceremony-seed";
/// Tag for an individual participant's entropy commitment.
pub const DOMAIN_CONTRIBUTION: &str = "W-TVC/v1/contribution";
/// Tag for the running ceremony transcript hash chain.
pub const DOMAIN_TRANSCRIPT: &str = "W-TVC/v1/transcript";
/// Tag binding a model descriptor to its ceremony.
pub const DOMAIN_MODEL_BINDING: &str = "W-TVC/v1/model-binding";
/// Tag for the 32-byte functional verification digest of a verifying key.
pub const DOMAIN_VK_DIGEST: &str = "W-TVC/v1/vk-digest";
/// Tag for the toxic-waste burn attestation.
pub const DOMAIN_BURN_ATTESTATION: &str = "W-TVC/v1/burn-attestation";
/// Tag for the BIP-340 sighash over a published parameter commitment.
pub const DOMAIN_COMMITMENT_SIGHASH: &str = "W-TVC/v1/commitment-sighash";

/// Computes a BIP-340 tagged hash over length-prefixed message parts.
pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let tag_digest = sha256::Hash::hash(tag.as_bytes()).to_byte_array();

    let mut engine = sha256::Hash::engine();
    engine.input(&tag_digest);
    engine.input(&tag_digest);
    for part in parts {
        engine.input(&(part.len() as u64).to_be_bytes());
        engine.input(part);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Folds a new element into a running hash chain.
///
/// Used to build the ceremony transcript so that each entry commits to every
/// entry before it. Truncating or reordering contributions changes the final
/// digest, which is what makes the published transcript auditable after the fact.
pub fn chain(tag: &str, previous: &[u8; 32], element: &[u8]) -> [u8; 32] {
    tagged_hash(tag, &[previous.as_slice(), element])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_tags_separate_identical_messages() {
        let message: &[u8] = b"same bytes";
        assert_ne!(
            tagged_hash(DOMAIN_VK_DIGEST, &[message]),
            tagged_hash(DOMAIN_TRANSCRIPT, &[message])
        );
    }

    #[test]
    fn length_prefixing_removes_concatenation_ambiguity() {
        assert_ne!(
            tagged_hash(DOMAIN_TRANSCRIPT, &[b"ab", b"c"]),
            tagged_hash(DOMAIN_TRANSCRIPT, &[b"a", b"bc"])
        );
    }

    #[test]
    fn chain_is_order_dependent() {
        let base = [0u8; 32];
        let forward = chain(DOMAIN_TRANSCRIPT, &chain(DOMAIN_TRANSCRIPT, &base, b"a"), b"b");
        let reverse = chain(DOMAIN_TRANSCRIPT, &chain(DOMAIN_TRANSCRIPT, &base, b"b"), b"a");
        assert_ne!(forward, reverse);
    }

    #[test]
    fn matches_bip340_reference_construction() {
        let tag = "W-TVC/v1/vk-digest";
        let tag_digest = sha256::Hash::hash(tag.as_bytes()).to_byte_array();
        let mut engine = sha256::Hash::engine();
        engine.input(&tag_digest);
        engine.input(&tag_digest);
        engine.input(&(3u64).to_be_bytes());
        engine.input(b"abc");
        let expected = sha256::Hash::from_engine(engine).to_byte_array();
        assert_eq!(tagged_hash(tag, &[b"abc"]), expected);
    }
}
__W_TVC_FILE_11__

echo "  tvc-core/src/hex.rs"
cat > 'tvc-core/src/hex.rs' <<'__W_TVC_FILE_12__'
//! Minimal lowercase hexadecimal codec.
//!
//! `tvc-core` carries its own hex implementation rather than pulling a
//! dependency. The protocol moves 32-byte digests and 64-byte signatures across
//! a Nostr relay boundary, so hex is on the trust path: every byte a wallet acts
//! on passes through [`decode`]. Keeping roughly forty auditable lines in-tree is
//! preferred over widening the supply chain for a trivial transformation.
//!
//! [`decode`] is strict by construction. It rejects uppercase input, odd-length
//! input, and any non-hex byte, so a digest string has exactly one valid
//! encoding. Accepting mixed case would let the same digest travel under two
//! spellings, and relay-level deduplication of commitments is easier to reason
//! about when the encoding is canonical.

use crate::error::{Result, TvcError};

const TABLE: &[u8; 16] = b"0123456789abcdef";

/// Encodes bytes as a lowercase hexadecimal string.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[usize::from(byte >> 4)] as char);
        out.push(TABLE[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Decodes a strict lowercase hexadecimal string into bytes.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        return Err(TvcError::MalformedHex(format!(
            "expected even length, got {}",
            text.len()
        )));
    }
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Decodes a strict lowercase hexadecimal string into a fixed-size array.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = decode(text)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| {
        TvcError::MalformedHex(format!("expected {} bytes, got {}", N, bytes.len()))
    })
}

fn nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(TvcError::MalformedHex(format!(
            "invalid lowercase hex byte: {:?}",
            byte as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_arbitrary_bytes() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn rejects_uppercase_and_odd_length() {
        assert!(decode("AB").is_err());
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
    }

    #[test]
    fn decode_array_enforces_width() {
        assert!(decode_array::<32>(&encode(&[0u8; 32])).is_ok());
        assert!(decode_array::<32>(&encode(&[0u8; 31])).is_err());
    }
}
__W_TVC_FILE_12__

echo "  tvc-core/src/error.rs"
cat > 'tvc-core/src/error.rs' <<'__W_TVC_FILE_13__'
//! Error taxonomy for the W-TVC protocol.
//!
//! Every fallible boundary in this crate returns [`TvcError`]. The variants are
//! deliberately coarse at the type level and precise in their payloads so that a
//! verifying wallet can branch on *class* of failure (is this a malformed input
//! or a cryptographic rejection?) without string matching.
//!
//! The distinction that matters operationally is between
//! [`TvcError::CommitmentMismatch`] and [`TvcError::ProofRejected`]:
//!
//! - `CommitmentMismatch` means the verifying key presented at runtime is not the
//!   key that was frozen by the ceremony. This is the model-substitution alarm:
//!   the proof may well be internally valid, but it was produced against a
//!   different circuit than the one the consortium attested to.
//! - `ProofRejected` means the verifying key was correct and the proof still
//!   failed to satisfy the pairing check. This is an invalid-execution alarm.
//!
//! Conflating the two would let a downgrading provider hide a model swap behind a
//! generic "verification failed", so they are kept structurally distinct.

use core::fmt;

/// Fallible result specialised to [`TvcError`].
pub type Result<T> = core::result::Result<T, TvcError>;

/// Every failure mode reachable through the public surface of `tvc-core`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TvcError {
    /// A ceremony was requested with no contributing participants.
    EmptyCeremony,
    /// Two participants presented the same identifier, breaking transcript
    /// auditability because contributions could no longer be attributed.
    DuplicateParticipant(String),
    /// The R1CS constraint system could not be synthesised.
    Synthesis(String),
    /// Canonical serialisation or deserialisation of an arkworks object failed.
    Codec(String),
    /// The runtime verifying key does not hash to the committed digest.
    CommitmentMismatch {
        /// Digest published by the ceremony and fetched from a Nostr relay.
        expected: String,
        /// Digest recomputed from the verifying key supplied at runtime.
        observed: String,
    },
    /// The Groth16 pairing check rejected the proof under a matching key.
    ProofRejected,
    /// A witness assignment was requested from a circuit holding no witness.
    MissingWitness,
    /// A byte string was not valid lowercase hexadecimal of the expected length.
    MalformedHex(String),
    /// A secp256k1 key, signature, or message was structurally invalid.
    Signature(String),
    /// The BIP-340 signature over a parameter commitment did not verify.
    CommitmentUnsigned,
    /// A model identifier contained a character that is unsafe to transport.
    InvalidIdentifier {
        /// Which descriptor field was rejected.
        field: &'static str,
        /// Why it was rejected.
        reason: String,
    },
    /// Ceremony artefacts describe a different model than the one they froze.
    ModelBindingMismatch {
        /// Binding digest recorded by the ceremony.
        expected: String,
        /// Binding digest recomputed from the descriptor read back from disk.
        observed: String,
    },
}

impl fmt::Display for TvcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCeremony => {
                write!(f, "ceremony requires at least one participant contribution")
            }
            Self::DuplicateParticipant(id) => {
                write!(f, "duplicate ceremony participant identifier: {id}")
            }
            Self::Synthesis(detail) => write!(f, "constraint synthesis failed: {detail}"),
            Self::Codec(detail) => write!(f, "canonical codec failure: {detail}"),
            Self::CommitmentMismatch { expected, observed } => write!(
                f,
                "parameter commitment mismatch: committed vk digest {expected}, runtime vk digest {observed}"
            ),
            Self::ProofRejected => {
                write!(f, "groth16 pairing check rejected the inference proof")
            }
            Self::MissingWitness => {
                write!(f, "circuit holds no witness assignment")
            }
            Self::MalformedHex(detail) => write!(f, "malformed hex encoding: {detail}"),
            Self::Signature(detail) => write!(f, "secp256k1 failure: {detail}"),
            Self::CommitmentUnsigned => {
                write!(f, "BIP-340 signature over parameter commitment did not verify")
            }
            Self::InvalidIdentifier { field, reason } => {
                write!(f, "invalid model {field}: {reason}")
            }
            Self::ModelBindingMismatch { expected, observed } => write!(
                f,
                "model binding mismatch: ceremony froze {expected}, descriptor on disk yields {observed}"
            ),
        }
    }
}

impl std::error::Error for TvcError {}

impl From<ark_serialize::SerializationError> for TvcError {
    fn from(value: ark_serialize::SerializationError) -> Self {
        Self::Codec(value.to_string())
    }
}

impl From<ark_relations::r1cs::SynthesisError> for TvcError {
    fn from(value: ark_relations::r1cs::SynthesisError) -> Self {
        Self::Synthesis(value.to_string())
    }
}

impl From<secp256k1::Error> for TvcError {
    fn from(value: secp256k1::Error) -> Self {
        Self::Signature(value.to_string())
    }
}
__W_TVC_FILE_13__

echo "  tvc-cli/Cargo.toml"
cat > 'tvc-cli/Cargo.toml' <<'__W_TVC_FILE_14__'
[package]
name = "tvc-cli"
description = "Operator and auditor command line for the W-TVC Protocol."
readme = "../README.md"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true

[[bin]]
name = "tvc"
path = "src/main.rs"

[dependencies]
tvc-core = { path = "../tvc-core", version = "0.1.0" }
ark-bn254.workspace = true
ark-ff.workspace = true
clap = { version = "4.6", features = ["derive"] }
getrandom = "0.3"

[lints.rust]
unsafe_code = "forbid"
__W_TVC_FILE_14__

echo "  tvc-cli/src/main.rs"
cat > 'tvc-cli/src/main.rs' <<'__W_TVC_FILE_15__'
//! `tvc` — operator and auditor command line for the W-TVC Protocol.
//!
//! Five subcommands cover the protocol's full lifecycle:
//!
//! | Command | Phase | Purpose |
//! |---|---|---|
//! | `ceremony` | Genesis | Run the setup, freeze the digest, burn the entropy. |
//! | `commit` | Genesis | Sign the commitment and emit a Nostr-ready payload. |
//! | `prove` | Runtime | Produce an inference proof against the proving key. |
//! | `verify` | Runtime | Check a proof against a committed digest. |
//! | `audit` | Anytime | Re-derive the digest and re-check a transcript. |
//! | `demo` | — | Run the whole lifecycle end to end, including a forged attempt. |
//!
//! Secrets never appear in argv. Signing keys are read from the `TVC_SECRET_KEY`
//! environment variable, because process arguments are world-readable through
//! `/proc` and land in shell history.

mod json;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ark_bn254::Fr;
use clap::{Parser, Subcommand};
use json::Json;
use tvc_core::error::TvcError;
use tvc_core::hex;
use tvc_core::{
    derive_vk_digest, field_from_u64, prove_inference, run_ceremony, verify_inference,
    CeremonyOutput, InferenceProof, ModelDescriptor, ParameterCommitment, ParticipantContribution,
    SignedCommitment, NOSTR_COMMITMENT_KIND, PROTOCOL_VERSION, SCHEME_TAG,
};

const SECRET_KEY_VAR: &str = "TVC_SECRET_KEY";

#[derive(Parser)]
#[command(
    name = "tvc",
    version,
    about = "Weight Threshold Verification Ceremony — freeze a model, prove an inference, verify without trust.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a Genesis Setup Ceremony and write its artefacts.
    Ceremony {
        /// Stable model identifier, for example `acme-llm-7b`.
        #[arg(long)]
        model_id: String,
        /// Frozen version string, for example `2026.09`.
        #[arg(long)]
        version: String,
        /// Human-readable architecture summary recorded in the transcript.
        #[arg(long, default_value = "affine-committed-inference")]
        architecture: String,
        /// Declared parameter count.
        #[arg(long, default_value_t = 7_000_000_000)]
        parameters: u64,
        /// Participant identifier; repeat once per contributor.
        #[arg(long = "participant", required = true)]
        participants: Vec<String>,
        /// Directory to write ceremony artefacts into.
        #[arg(long, default_value = "ceremony-out")]
        out: PathBuf,
    },
    /// Sign a ceremony's commitment and emit a Nostr-ready payload.
    Commit {
        /// Directory holding ceremony artefacts.
        #[arg(long, default_value = "ceremony-out")]
        setup: PathBuf,
    },
    /// Produce an inference proof.
    Prove {
        /// Directory holding ceremony artefacts.
        #[arg(long, default_value = "ceremony-out")]
        setup: PathBuf,
        /// Private weight parameter.
        #[arg(long)]
        weight: u64,
        /// Private bias parameter.
        #[arg(long)]
        bias: u64,
        /// Public input activation.
        #[arg(long)]
        input: u64,
    },
    /// Verify an inference proof against a committed digest.
    Verify {
        /// Directory holding ceremony and proof artefacts.
        #[arg(long, default_value = "ceremony-out")]
        setup: PathBuf,
        /// Committed verification digest, as fetched from a Nostr relay.
        #[arg(long)]
        digest: String,
    },
    /// Re-derive the digest and re-check the transcript hash chain.
    Audit {
        /// Directory holding ceremony artefacts.
        #[arg(long, default_value = "ceremony-out")]
        setup: PathBuf,
    },
    /// Run the full lifecycle end to end, including a rejected forgery.
    Demo {
        /// Directory to write demo artefacts into.
        #[arg(long, default_value = "demo-out")]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Ceremony {
            model_id,
            version,
            architecture,
            parameters,
            participants,
            out,
        } => report(ceremony(
            &model_id,
            &version,
            &architecture,
            parameters,
            &participants,
            &out,
        )),
        Command::Commit { setup } => report(commit(&setup)),
        Command::Prove {
            setup,
            weight,
            bias,
            input,
        } => report(prove(&setup, weight, bias, input)),
        Command::Verify { setup, digest } => report(verify(&setup, &digest)),
        Command::Audit { setup } => report(audit(&setup)),
        Command::Demo { out } => report(demo(&out)),
    }
}

fn report(outcome: Result<(), String>) -> ExitCode {
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn ceremony(
    model_id: &str,
    version: &str,
    architecture: &str,
    parameters: u64,
    participants: &[String],
    out: &Path,
) -> Result<(), String> {
    let model = ModelDescriptor::new(model_id, version, architecture, parameters);
    model.validate().map_err(describe)?;

    let mut contributions = Vec::with_capacity(participants.len());
    for participant in participants {
        contributions.push(ParticipantContribution::new(participant, os_entropy()?));
    }

    println!("Genesis Setup Ceremony");
    println!("  model      {}", model.address());
    println!("  arch       {architecture}");
    println!("  parties    {}", participants.len());

    let output = run_ceremony(model, contributions).map_err(describe)?;
    write_ceremony(out, &output)?;

    println!();
    println!("  vk digest        {}", output.vk_digest_hex());
    println!("  transcript       {}", output.transcript_digest_hex());
    println!("  burn attestation {}", output.burn.attestation_hex());
    println!("  entropy burned   {} bytes across {} contributions", output.burn.burned_bytes, output.burn.contributions);
    println!();
    println!("  artefacts written to {}", out.display());
    println!("  next: tvc commit --setup {}", out.display());
    Ok(())
}

fn commit(setup: &Path) -> Result<(), String> {
    let descriptor = read_descriptor(setup)?;
    verify_model_binding(setup, &descriptor)?;
    let vk_digest = read_digest(&setup.join("vk_digest.hex"))?;
    let transcript_digest = read_digest(&setup.join("transcript_digest.hex"))?;
    let burn_digest = read_digest(&setup.join("burn_digest.hex"))?;

    let secret_key = read_secret_key()?;
    let commitment = ParameterCommitment::new(
        descriptor.model_id.clone(),
        descriptor.version.clone(),
        vk_digest,
        transcript_digest,
        burn_digest,
    );
    let signed = commitment
        .sign(&secret_key, &os_entropy()?)
        .map_err(describe)?;
    signed.verify().map_err(describe)?;

    let path = write_commitment(setup, &signed)?;

    println!("Signed parameter commitment");
    println!("  address    {}", signed.commitment.address());
    println!("  vk digest  {}", signed.commitment.vk_digest_hex());
    println!("  signer     {}", signed.signer_hex());
    println!("  signature  verified locally before writing");
    println!();
    println!("  payload written to {}", path.display());
    let hint = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    println!("  next: cd nostr-bridge && npm run broadcast -- --commitment {}", hint.display());
    Ok(())
}

fn prove(setup: &Path, weight: u64, bias: u64, input: u64) -> Result<(), String> {
    let proving_key = read_bytes(&setup.join("proving_key.bin"))?;
    let proof = prove_inference(
        &proving_key,
        field_from_u64(weight),
        field_from_u64(bias),
        field_from_u64(input),
        os_entropy()?,
    )
    .map_err(describe)?;

    write_proof(setup, &proof)?;

    println!("Inference proof generated");
    println!("  witness    weight and bias held privately, never serialised");
    println!("  proof      {} bytes", proof.proof.len());
    println!("  artefacts  {}", setup.join("proof.bin").display());
    Ok(())
}

fn verify(setup: &Path, digest: &str) -> Result<(), String> {
    let verifying_key = read_bytes(&setup.join("verifying_key.bin"))?;
    let proof = read_bytes(&setup.join("proof.bin"))?;
    let public_inputs = read_public_inputs(&setup.join("public_inputs.txt"))?;
    let committed: [u8; 32] = hex::decode_array(digest.trim()).map_err(describe)?;

    match verify_inference(&verifying_key, &committed, &public_inputs, &proof) {
        Ok(report) => {
            println!("ACCEPTED");
            println!("  commitment  runtime key matches the digest published to Nostr");
            println!("  proof       groth16 pairing check passed");
            println!("  vk digest   {}", hex::encode(&report.observed_vk_digest));
            Ok(())
        }
        Err(TvcError::CommitmentMismatch { expected, observed }) => Err(format!(
            "REJECTED — model substitution detected\n  committed digest {expected}\n  runtime digest   {observed}\n  the proof may be internally valid, but it was produced against a different circuit"
        )),
        Err(TvcError::ProofRejected) => Err(
            "REJECTED — the verifying key was correct and the pairing check still failed".to_owned(),
        ),
        Err(other) => Err(describe(other)),
    }
}

fn audit(setup: &Path) -> Result<(), String> {
    let verifying_key = read_bytes(&setup.join("verifying_key.bin"))?;
    let recorded = read_digest(&setup.join("vk_digest.hex"))?;
    let recomputed = derive_vk_digest(&verifying_key);

    println!("Audit");
    println!("  recorded    {}", hex::encode(&recorded));
    println!("  recomputed  {}", hex::encode(&recomputed));

    if recorded != recomputed {
        return Err("digest on disk does not match the verifying key beside it".to_owned());
    }
    println!("  result      digest reproduces from the verifying key");
    Ok(())
}

fn demo(out: &Path) -> Result<(), String> {
    let honest_dir = out.join("honest");
    let rogue_dir = out.join("rogue");

    println!("== Phase 1: Genesis Setup Ceremony ==");
    let honest = run_ceremony(
        ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 7_000_000_000),
        vec![
            ParticipantContribution::new("bitshala", os_entropy()?),
            ParticipantContribution::new("acme-labs", os_entropy()?),
            ParticipantContribution::new("independent-auditor", os_entropy()?),
        ],
    )
    .map_err(describe)?;
    write_ceremony(&honest_dir, &honest)?;

    println!("  committed digest  {}", honest.vk_digest_hex());
    println!("  transcript chain  {}", if honest.transcript.verify_chain() { "verified" } else { "BROKEN" });
    println!("  entropy burned    {} bytes", honest.burn.burned_bytes);

    let demo_key = os_entropy()?;
    let signed = ParameterCommitment::new(
        "acme-llm-7b",
        "2026.09",
        honest.vk_digest,
        honest.transcript.final_digest,
        honest.burn.attestation_digest,
    )
    .sign(&demo_key, &os_entropy()?)
    .map_err(describe)?;
    signed.verify().map_err(describe)?;
    let commitment_path = write_commitment(&honest_dir, &signed)?;
    println!("  signed by         {} (ephemeral demo key)", signed.signer_hex());

    println!();
    println!("== Phase 2: honest runtime inference ==");
    let honest_proof = prove_inference(
        &honest.proving_key,
        field_from_u64(7),
        field_from_u64(3),
        field_from_u64(11),
        os_entropy()?,
    )
    .map_err(describe)?;
    let accepted = verify_inference(
        &honest.verifying_key,
        &honest.vk_digest,
        &honest_proof.public_inputs,
        &honest_proof.proof,
    )
    .map_err(describe)?;
    println!("  wallet verdict    {}", if accepted.accepted() { "ACCEPTED" } else { "rejected" });

    println!();
    println!("== Phase 2 under attack: silent model downgrade ==");
    let rogue = run_ceremony(
        ModelDescriptor::new("acme-llm-7b", "2026.09", "affine-committed-inference", 1_500_000_000),
        vec![ParticipantContribution::new("rogue-operator", os_entropy()?)],
    )
    .map_err(describe)?;
    write_ceremony(&rogue_dir, &rogue)?;

    let rogue_proof = prove_inference(
        &rogue.proving_key,
        field_from_u64(7),
        field_from_u64(3),
        field_from_u64(11),
        os_entropy()?,
    )
    .map_err(describe)?;

    let self_consistent = verify_inference(
        &rogue.verifying_key,
        &rogue.vk_digest,
        &rogue_proof.public_inputs,
        &rogue_proof.proof,
    )
    .map_err(describe)?;
    println!("  rogue proof is internally valid against its own key: {}", self_consistent.accepted());

    match verify_inference(
        &rogue.verifying_key,
        &honest.vk_digest,
        &rogue_proof.public_inputs,
        &rogue_proof.proof,
    ) {
        Err(TvcError::CommitmentMismatch { expected, observed }) => {
            println!("  wallet verdict    REJECTED");
            println!("    committed       {expected}");
            println!("    runtime         {observed}");
            println!();
            println!("  A valid proof about the wrong model is still refused, because the");
            println!("  commitment is checked before the proof. This is the downgrade defence.");
            println!();
            println!("== Next: publish the commitment to Nostr ==");
            println!("  The demo signed with a throwaway key. Hand the same key to the bridge so");
            println!("  the Nostr identity matches the commitment signer, then broadcast:");
            println!();
            println!("    export TVC_SECRET_KEY={}", hex::encode(&demo_key));
            println!("    cd nostr-bridge && npm install");
            println!("    npm run broadcast -- --commitment ../{}", commitment_path.display());
            println!();
            println!("  That is a demo key with no value. A real ceremony key never leaves");
            println!("  the environment and is never printed.");
            Ok(())
        }
        Err(other) => Err(format!("demo produced an unexpected failure: {}", describe(other))),
        Ok(_) => Err("demo invariant broken: a substituted model was accepted".to_owned()),
    }
}

fn write_ceremony(out: &Path, output: &CeremonyOutput) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|error| error.to_string())?;
    write_file(&out.join("verifying_key.bin"), &output.verifying_key)?;
    write_file(&out.join("proving_key.bin"), &output.proving_key)?;
    write_text(&out.join("vk_digest.hex"), &output.vk_digest_hex())?;
    write_text(&out.join("transcript_digest.hex"), &output.transcript_digest_hex())?;
    write_text(&out.join("burn_digest.hex"), &output.burn.attestation_hex())?;
    write_text(
        &out.join("model_binding.hex"),
        &hex::encode(&output.transcript.model.binding_digest()),
    )?;
    write_text(
        &out.join("model.txt"),
        &format!(
            "{}\n{}\n{}\n{}",
            output.transcript.model.model_id,
            output.transcript.model.version,
            output.transcript.model.architecture,
            output.transcript.model.parameter_count
        ),
    )?;

    let records = output
        .transcript
        .records
        .iter()
        .map(|record| {
            Json::obj(vec![
                ("index", Json::Num(u64::from(record.index))),
                ("participant_id", Json::s(&record.participant_id)),
                ("commitment", Json::s(hex::encode(&record.commitment))),
                ("running_digest", Json::s(hex::encode(&record.running_digest))),
            ])
        })
        .collect::<Vec<_>>();

    let transcript = Json::obj(vec![
        ("protocol", Json::s(PROTOCOL_VERSION)),
        ("scheme", Json::s(SCHEME_TAG)),
        ("model_id", Json::s(&output.transcript.model.model_id)),
        ("version", Json::s(&output.transcript.model.version)),
        ("architecture", Json::s(&output.transcript.model.architecture)),
        ("parameter_count", Json::Num(output.transcript.model.parameter_count)),
        ("vk_digest", Json::s(output.vk_digest_hex())),
        ("final_digest", Json::s(output.transcript_digest_hex())),
        ("chain_verified", Json::s(output.transcript.verify_chain().to_string())),
        ("contributions", Json::Arr(records)),
        (
            "burn",
            Json::obj(vec![
                ("attestation_digest", Json::s(output.burn.attestation_hex())),
                ("contributions", Json::Num(output.burn.contributions as u64)),
                ("burned_bytes", Json::Num(output.burn.burned_bytes as u64)),
            ]),
        ),
    ]);
    write_text(&out.join("transcript.json"), &transcript.render(0))
}

fn write_commitment(setup: &Path, signed: &SignedCommitment) -> Result<PathBuf, String> {
    let payload = Json::obj(vec![
        ("protocol", Json::s(PROTOCOL_VERSION)),
        ("kind", Json::Num(u64::from(NOSTR_COMMITMENT_KIND))),
        ("address", Json::s(signed.commitment.address())),
        ("model_id", Json::s(&signed.commitment.model_id)),
        ("version", Json::s(&signed.commitment.version)),
        ("scheme", Json::s(&signed.commitment.scheme)),
        ("vk_digest", Json::s(hex::encode(&signed.commitment.vk_digest))),
        ("transcript_digest", Json::s(hex::encode(&signed.commitment.transcript_digest))),
        ("burn_digest", Json::s(hex::encode(&signed.commitment.burn_digest))),
        ("signer", Json::s(signed.signer_hex())),
        ("signature", Json::s(signed.signature_hex())),
    ]);
    let path = setup.join("commitment.json");
    fs::write(&path, format!("{}\n", payload.render(0)))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

fn write_proof(setup: &Path, proof: &InferenceProof) -> Result<(), String> {
    write_file(&setup.join("proof.bin"), &proof.proof)?;
    let encoded = proof.public_inputs_hex().map_err(describe)?;
    write_text(&setup.join("public_inputs.txt"), &encoded.join("\n"))
}

fn read_public_inputs(path: &Path) -> Result<Vec<Fr>, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let values: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    InferenceProof::public_inputs_from_hex(&values).map_err(describe)
}

fn read_descriptor(setup: &Path) -> Result<ModelDescriptor, String> {
    let path = setup.join("model.txt");
    let text = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 4 {
        return Err(format!(
            "{} is malformed: expected 4 lines, found {}",
            path.display(),
            lines.len()
        ));
    }
    let parameter_count = lines[3]
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("{}: parameter count is not a number: {error}", path.display()))?;

    let descriptor = ModelDescriptor::new(
        lines[0].trim(),
        lines[1].trim(),
        lines[2].trim(),
        parameter_count,
    );
    descriptor.validate().map_err(describe)?;
    Ok(descriptor)
}

fn verify_model_binding(setup: &Path, descriptor: &ModelDescriptor) -> Result<(), String> {
    let path = setup.join("model_binding.hex");
    let recorded = read_digest(&path).map_err(|error| {
        format!("{error}\n  This ceremony predates model-binding checks. Re-run `tvc ceremony`.")
    })?;
    let recomputed = descriptor.binding_digest();
    if recorded != recomputed {
        return Err(describe(TvcError::ModelBindingMismatch {
            expected: hex::encode(&recorded),
            observed: hex::encode(&recomputed),
        }));
    }
    Ok(())
}

fn read_digest(path: &Path) -> Result<[u8; 32], String> {
    let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    hex::decode_array(text.trim()).map_err(describe)
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn write_text(path: &Path, text: &str) -> Result<(), String> {
    write_file(path, format!("{text}\n").as_bytes())
}

fn read_secret_key() -> Result<[u8; 32], String> {
    let raw = std::env::var(SECRET_KEY_VAR).map_err(|_| {
        format!(
            "{SECRET_KEY_VAR} is not set.\n  Signing keys are read from the environment so they never appear in argv or shell history.\n  Generate one with:  export {SECRET_KEY_VAR}=$(openssl rand -hex 32)"
        )
    })?;
    hex::decode_array(raw.trim()).map_err(|error| {
        format!("{SECRET_KEY_VAR} must be 64 lowercase hex characters: {error}")
    })
}

fn os_entropy() -> Result<[u8; 32], String> {
    let mut buffer = [0u8; 32];
    getrandom::fill(&mut buffer)
        .map_err(|error| format!("operating system CSPRNG unavailable: {error}"))?;
    Ok(buffer)
}

fn describe(error: TvcError) -> String {
    error.to_string()
}
__W_TVC_FILE_15__

echo "  tvc-cli/src/json.rs"
cat > 'tvc-cli/src/json.rs' <<'__W_TVC_FILE_16__'
//! Minimal JSON serialisation for artefacts this CLI emits.
//!
//! The CLI only ever *writes* JSON; the `nostr-bridge` TypeScript workspace is
//! what reads it. A writer is a few dozen auditable lines, whereas a full serde
//! dependency tree would be pulled in purely to format artefacts that already
//! have a fixed shape. Keeping the dependency surface small is a deliberate
//! posture for a tool that handles ceremony output.

/// A JSON value restricted to the shapes this CLI emits.
pub enum Json {
    /// A JSON string, escaped on render.
    Str(String),
    /// A JSON number rendered from an unsigned integer.
    Num(u64),
    /// A JSON array.
    Arr(Vec<Json>),
    /// A JSON object, rendered in insertion order.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Builds a string value.
    pub fn s(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    /// Builds an object from key-value pairs.
    pub fn obj(fields: Vec<(&str, Json)>) -> Self {
        Self::Obj(
            fields
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    /// Renders the value as indented JSON text.
    pub fn render(&self, indent: usize) -> String {
        let pad = "  ".repeat(indent);
        let inner_pad = "  ".repeat(indent + 1);
        match self {
            Self::Str(value) => format!("\"{}\"", escape(value)),
            Self::Num(value) => value.to_string(),
            Self::Arr(items) if items.is_empty() => "[]".to_owned(),
            Self::Arr(items) => {
                let body = items
                    .iter()
                    .map(|item| format!("{inner_pad}{}", item.render(indent + 1)))
                    .collect::<Vec<_>>()
                    .join(",\n");
                format!("[\n{body}\n{pad}]")
            }
            Self::Obj(fields) if fields.is_empty() => "{}".to_owned(),
            Self::Obj(fields) => {
                let body = fields
                    .iter()
                    .map(|(key, value)| {
                        format!("{inner_pad}\"{}\": {}", escape(key), value.render(indent + 1))
                    })
                    .collect::<Vec<_>>()
                    .join(",\n");
                format!("{{\n{body}\n{pad}}}")
            }
        }
    }
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_quote_characters() {
        let value = Json::s("a\"b\\c\nd\u{1}");
        assert_eq!(value.render(0), "\"a\\\"b\\\\c\\nd\\u0001\"");
    }

    #[test]
    fn renders_nested_objects_in_insertion_order() {
        let value = Json::obj(vec![
            ("b", Json::Num(2)),
            ("a", Json::Arr(vec![Json::s("x")])),
        ]);
        let rendered = value.render(0);
        assert!(rendered.find("\"b\"").unwrap() < rendered.find("\"a\"").unwrap());
        assert!(rendered.contains("\"x\""));
    }
}
__W_TVC_FILE_16__

echo "  nostr-bridge/package.json"
cat > 'nostr-bridge/package.json' <<'__W_TVC_FILE_17__'
{
  "name": "@w-tvc/nostr-bridge",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "license": "MIT",
  "engines": { "node": ">=20" },
  "scripts": {
    "broadcast": "tsx src/broadcast.ts",
    "fetch": "tsx src/fetch.ts",
    "typecheck": "tsc --noEmit",
    "test": "tsx --test src/*.test.ts"
  },
  "dependencies": {
    "nostr-tools": "^2.10.4"
  },
  "devDependencies": {
    "@types/node": "^22.10.2",
    "tsx": "^4.19.2",
    "typescript": "^5.7.2"
  }
}
__W_TVC_FILE_17__

echo "  nostr-bridge/tsconfig.json"
cat > 'nostr-bridge/tsconfig.json' <<'__W_TVC_FILE_18__'
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2023"],
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "types": ["node"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "noFallthroughCasesInSwitch": true,
    "exactOptionalPropertyTypes": true,
    "verbatimModuleSyntax": true,
    "erasableSyntaxOnly": true,
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "noEmit": true
  },
  "include": ["src/**/*.ts"]
}
__W_TVC_FILE_18__

echo "  nostr-bridge/src/commitment.ts"
cat > 'nostr-bridge/src/commitment.ts' <<'__W_TVC_FILE_19__'
import { readFile } from 'node:fs/promises'

export const PROTOCOL_VERSION = 'w-tvc/1'
export const COMMITMENT_KIND = 30200

export type ParameterCommitment = {
  protocol: string
  kind: number
  address: string
  model_id: string
  version: string
  scheme: string
  vk_digest: string
  transcript_digest: string
  burn_digest: string
  signer: string
  signature: string
}

const HEX_32 = /^[0-9a-f]{64}$/
const HEX_64 = /^[0-9a-f]{128}$/

export class CommitmentError extends Error {}

function requireString(source: Record<string, unknown>, field: string): string {
  const value = source[field]
  if (typeof value !== 'string' || value.length === 0) {
    throw new CommitmentError(`commitment field "${field}" is missing or not a string`)
  }
  return value
}

function requireHex(source: Record<string, unknown>, field: string, pattern: RegExp): string {
  const value = requireString(source, field)
  if (!pattern.test(value)) {
    throw new CommitmentError(
      `commitment field "${field}" must be lowercase hex of the expected width, got "${value}"`,
    )
  }
  return value
}

export function parseCommitment(raw: unknown): ParameterCommitment {
  if (typeof raw !== 'object' || raw === null) {
    throw new CommitmentError('commitment payload is not a JSON object')
  }
  const source = raw as Record<string, unknown>

  const protocol = requireString(source, 'protocol')
  if (protocol !== PROTOCOL_VERSION) {
    throw new CommitmentError(`unsupported protocol "${protocol}", expected "${PROTOCOL_VERSION}"`)
  }

  const kind = source['kind']
  if (kind !== COMMITMENT_KIND) {
    throw new CommitmentError(`unsupported kind ${String(kind)}, expected ${COMMITMENT_KIND}`)
  }

  const commitment: ParameterCommitment = {
    protocol,
    kind: COMMITMENT_KIND,
    address: requireString(source, 'address'),
    model_id: requireString(source, 'model_id'),
    version: requireString(source, 'version'),
    scheme: requireString(source, 'scheme'),
    vk_digest: requireHex(source, 'vk_digest', HEX_32),
    transcript_digest: requireHex(source, 'transcript_digest', HEX_32),
    burn_digest: requireHex(source, 'burn_digest', HEX_32),
    signer: requireHex(source, 'signer', HEX_32),
    signature: requireHex(source, 'signature', HEX_64),
  }

  const derived = `${commitment.model_id}:${commitment.version}`
  if (commitment.address !== derived) {
    throw new CommitmentError(
      `address "${commitment.address}" does not match model and version "${derived}"`,
    )
  }

  return commitment
}

export async function loadCommitment(path: string): Promise<ParameterCommitment> {
  let text: string
  try {
    text = await readFile(path, 'utf8')
  } catch (cause) {
    throw new CommitmentError(`cannot read commitment at ${path}: ${String(cause)}`)
  }
  try {
    return parseCommitment(JSON.parse(text))
  } catch (cause) {
    if (cause instanceof CommitmentError) throw cause
    throw new CommitmentError(`commitment at ${path} is not valid JSON: ${String(cause)}`)
  }
}
__W_TVC_FILE_19__

echo "  nostr-bridge/src/event.ts"
cat > 'nostr-bridge/src/event.ts' <<'__W_TVC_FILE_20__'
import { finalizeEvent, verifyEvent } from 'nostr-tools/pure'
import type { Event, EventTemplate } from 'nostr-tools/pure'

import { COMMITMENT_KIND, PROTOCOL_VERSION, type ParameterCommitment } from './commitment.ts'

export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.primal.net',
  'wss://nostr.mom',
]

export function buildEventTemplate(
  commitment: ParameterCommitment,
  createdAt: number = Math.floor(Date.now() / 1000),
): EventTemplate {
  return {
    kind: COMMITMENT_KIND,
    created_at: createdAt,
    tags: [
      ['d', commitment.address],
      ['vk', commitment.vk_digest],
      ['model', commitment.model_id],
      ['ver', commitment.version],
      ['alg', commitment.scheme],
      ['transcript', commitment.transcript_digest],
      ['burn', commitment.burn_digest],
      ['signer', commitment.signer],
      ['bip340', commitment.signature],
      ['protocol', PROTOCOL_VERSION],
      ['t', 'w-tvc'],
    ],
    content: JSON.stringify(commitment),
  }
}

export function signEvent(
  commitment: ParameterCommitment,
  secretKey: Uint8Array,
  createdAt?: number,
): Event {
  const template =
    createdAt === undefined
      ? buildEventTemplate(commitment)
      : buildEventTemplate(commitment, createdAt)
  const event = finalizeEvent(template, secretKey)
  if (!verifyEvent(event)) {
    throw new Error('finalizeEvent produced an event that failed verification')
  }
  return event
}

export function coordinatesFor(commitment: ParameterCommitment, pubkey: string): string {
  return `${COMMITMENT_KIND}:${pubkey}:${commitment.address}`
}

export function tagValue(event: Pick<Event, 'tags'>, name: string): string | undefined {
  for (const tag of event.tags) {
    if (tag[0] === name) return tag[1]
  }
  return undefined
}
__W_TVC_FILE_20__

echo "  nostr-bridge/src/broadcast.ts"
cat > 'nostr-bridge/src/broadcast.ts' <<'__W_TVC_FILE_21__'
import { parseArgs } from 'node:util'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import type { Event } from 'nostr-tools/pure'
import { npubEncode, naddrEncode, nsecEncode } from 'nostr-tools/nip19'
import { SimplePool } from 'nostr-tools/pool'

import { COMMITMENT_KIND, loadCommitment, type ParameterCommitment } from './commitment.ts'
import { DEFAULT_RELAYS, coordinatesFor, signEvent } from './event.ts'

const SECRET_KEY_VAR = 'TVC_SECRET_KEY'

type KeySource = 'environment' | 'generated'

type ResolvedKey = {
  secretKey: Uint8Array
  publicKey: string
  source: KeySource
}

function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(`${SECRET_KEY_VAR} must be 64 lowercase hex characters`)
  }
  const bytes = new Uint8Array(32)
  for (let index = 0; index < 32; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

function resolveKey(): ResolvedKey {
  const fromEnvironment = process.env[SECRET_KEY_VAR]
  if (fromEnvironment && fromEnvironment.trim().length > 0) {
    const secretKey = hexToBytes(fromEnvironment.trim())
    return { secretKey, publicKey: getPublicKey(secretKey), source: 'environment' }
  }
  const secretKey = generateSecretKey()
  return { secretKey, publicKey: getPublicKey(secretKey), source: 'generated' }
}

function reportKeyBinding(commitment: ParameterCommitment, key: ResolvedKey): boolean {
  const bound = key.publicKey === commitment.signer
  console.log('Publishing identity')
  console.log(`  source     ${key.source === 'environment' ? `${SECRET_KEY_VAR}` : 'freshly generated (ephemeral)'}`)
  console.log(`  pubkey     ${key.publicKey}`)
  console.log(`  npub       ${npubEncode(key.publicKey)}`)

  if (bound) {
    console.log('  binding    matches the BIP-340 signer inside the commitment')
    return true
  }

  console.log(`  binding    DOES NOT match the commitment signer ${commitment.signer}`)
  console.log('')
  console.log('  The commitment carries its own BIP-340 signature made by the ceremony key.')
  console.log('  Publishing it from a different Nostr identity still produces a valid event,')
  console.log('  but a wallet pinning the ceremony key will ignore it. For a real broadcast,')
  console.log(`  export ${SECRET_KEY_VAR} to the same key used by "tvc commit".`)
  if (key.source === 'generated') {
    console.log(`  Ephemeral nsec (demo only): ${nsecEncode(key.secretKey)}`)
  }
  return false
}

function describeEvent(event: Event, commitment: ParameterCommitment): void {
  console.log('')
  console.log(`Kind ${COMMITMENT_KIND} parameter commitment event`)
  console.log(`  id         ${event.id}`)
  console.log(`  pubkey     ${event.pubkey}`)
  console.log(`  created_at ${event.created_at}`)
  console.log(`  d tag      ${commitment.address}`)
  console.log(`  vk digest  ${commitment.vk_digest}`)
  console.log(`  coordinate ${coordinatesFor(commitment, event.pubkey)}`)
  console.log(`  naddr      ${naddrEncode({ identifier: commitment.address, pubkey: event.pubkey, kind: COMMITMENT_KIND })}`)
}

async function publishLive(event: Event, relays: string[]): Promise<number> {
  const pool = new SimplePool()
  let accepted = 0
  try {
    const results = await Promise.allSettled(pool.publish(relays, event))
    results.forEach((result, index) => {
      const relay = relays[index] ?? 'unknown relay'
      if (result.status === 'fulfilled') {
        accepted += 1
        console.log(`  accepted  ${relay}`)
      } else {
        console.log(`  refused   ${relay} — ${String(result.reason)}`)
      }
    })
  } finally {
    pool.close(relays)
  }
  return accepted
}

function publishDryRun(event: Event, relays: string[]): void {
  for (const relay of relays) {
    console.log(`  would send  ${relay}`)
  }
  console.log('')
  console.log('  Wire payload:')
  console.log(`  ${JSON.stringify(['EVENT', event])}`)
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: {
      commitment: { type: 'string', short: 'c' },
      relay: { type: 'string', multiple: true, short: 'r' },
      live: { type: 'boolean', default: false },
      'created-at': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
    allowPositionals: false,
  })

  if (values.help || !values.commitment) {
    console.log('Usage: npm run broadcast -- --commitment <path/to/commitment.json> [options]')
    console.log('')
    console.log('Options:')
    console.log('  -c, --commitment <path>  Commitment payload emitted by "tvc commit". Required.')
    console.log('  -r, --relay <url>        Relay to target; repeatable. Defaults to four public relays.')
    console.log('      --created-at <unix>  Pin created_at for a reproducible event id.')
    console.log('      --live               Actually publish. Omitted, the script only simulates.')
    console.log('  -h, --help               Show this message.')
    console.log('')
    console.log(`Signing key is read from ${SECRET_KEY_VAR}; without it an ephemeral key is generated.`)
    return values.help ? 0 : 1
  }

  const commitment = await loadCommitment(values.commitment)
  const relays = values.relay && values.relay.length > 0 ? values.relay : DEFAULT_RELAYS

  console.log('W-TVC parameter commitment broadcast')
  console.log(`  model      ${commitment.model_id} ${commitment.version}`)
  console.log(`  scheme     ${commitment.scheme}`)
  console.log('')

  const key = resolveKey()
  const bound = reportKeyBinding(commitment, key)

  const createdAt = values['created-at'] ? Number.parseInt(values['created-at'], 10) : undefined
  if (createdAt !== undefined && !Number.isFinite(createdAt)) {
    throw new Error('--created-at must be a Unix timestamp in seconds')
  }

  const event = signEvent(commitment, key.secretKey, createdAt)

  describeEvent(event, commitment)

  console.log('')
  if (values.live) {
    if (!bound) {
      console.log('Refusing to publish live from a key that does not match the commitment signer.')
      console.log(`Set ${SECRET_KEY_VAR} to the ceremony key, or drop --live to simulate.`)
      return 1
    }
    console.log(`Publishing to ${relays.length} relays`)
    const accepted = await publishLive(event, relays)
    console.log('')
    console.log(`  ${accepted}/${relays.length} relays accepted the commitment`)
    return accepted > 0 ? 0 : 1
  }

  console.log(`Simulating publication to ${relays.length} relays (no network traffic)`)
  publishDryRun(event, relays)
  console.log('')
  console.log('  Dry run only. Re-run with --live to publish for real.')
  return 0
}

main()
  .then((code) => {
    process.exitCode = code
  })
  .catch((error: unknown) => {
    console.error(`error: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  })
__W_TVC_FILE_21__

echo "  nostr-bridge/src/fetch.ts"
cat > 'nostr-bridge/src/fetch.ts' <<'__W_TVC_FILE_22__'
import { parseArgs } from 'node:util'
import { verifyEvent } from 'nostr-tools/pure'
import type { Event } from 'nostr-tools/pure'
import { SimplePool } from 'nostr-tools/pool'

import { COMMITMENT_KIND, parseCommitment, type ParameterCommitment } from './commitment.ts'
import { DEFAULT_RELAYS, tagValue } from './event.ts'

type Resolution = {
  event: Event
  commitment: ParameterCommitment
}

function reconcile(event: Event): Resolution {
  if (!verifyEvent(event)) {
    throw new Error(`event ${event.id} carries an invalid Nostr signature`)
  }

  const commitment = parseCommitment(JSON.parse(event.content))

  const mismatches: string[] = []
  const expectations: Array<[string, string]> = [
    ['d', commitment.address],
    ['vk', commitment.vk_digest],
    ['model', commitment.model_id],
    ['ver', commitment.version],
    ['alg', commitment.scheme],
    ['transcript', commitment.transcript_digest],
    ['burn', commitment.burn_digest],
    ['signer', commitment.signer],
    ['bip340', commitment.signature],
  ]
  for (const [name, expected] of expectations) {
    const actual = tagValue(event, name)
    if (actual !== expected) {
      mismatches.push(`  tag "${name}": tag says ${String(actual)}, content says ${expected}`)
    }
  }
  if (mismatches.length > 0) {
    throw new Error(`event ${event.id} has tags disagreeing with its content:\n${mismatches.join('\n')}`)
  }

  return { event, commitment }
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: {
      address: { type: 'string', short: 'a' },
      author: { type: 'string' },
      relay: { type: 'string', multiple: true, short: 'r' },
      timeout: { type: 'string', default: '8000' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
    allowPositionals: false,
  })

  if (values.help || !values.address) {
    console.log('Usage: npm run fetch -- --address <model_id:version> [options]')
    console.log('')
    console.log('Options:')
    console.log('  -a, --address <id:ver>  Model address to resolve. Required.')
    console.log('      --author <hex>      Pin the consortium pubkey. Strongly recommended.')
    console.log('  -r, --relay <url>       Relay to query; repeatable.')
    console.log('      --timeout <ms>      Query timeout, default 8000.')
    console.log('  -h, --help              Show this message.')
    console.log('')
    console.log('Without --author this resolves whatever any relay serves, which is not a')
    console.log('trust anchor. A wallet must pin the key whose commitments it honours.')
    return values.help ? 0 : 1
  }

  const relays = values.relay && values.relay.length > 0 ? values.relay : DEFAULT_RELAYS
  const timeout = Number.parseInt(values.timeout ?? '8000', 10)
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new Error('--timeout must be a positive number of milliseconds')
  }

  const filter: { kinds: number[]; '#d': string[]; authors?: string[] } = {
    kinds: [COMMITMENT_KIND],
    '#d': [values.address],
  }
  if (values.author) {
    filter.authors = [values.author]
  }

  console.log('Resolving W-TVC parameter commitment')
  console.log(`  address  ${values.address}`)
  console.log(`  author   ${values.author ?? 'ANY (not a trust anchor)'}`)
  console.log(`  relays   ${relays.join(', ')}`)
  console.log('')

  const pool = new SimplePool()
  let events: Event[]
  try {
    events = await pool.querySync(relays, filter, { maxWait: timeout })
  } finally {
    pool.close(relays)
  }

  if (events.length === 0) {
    console.log('No commitment found. The model version may not have completed its ceremony,')
    console.log('or none of the queried relays carry it.')
    return 1
  }

  events.sort((left, right) => right.created_at - left.created_at)
  const newest = events[0]
  if (!newest) {
    return 1
  }

  const { commitment } = reconcile(newest)

  console.log(`Found ${events.length} event(s); using the most recent.`)
  console.log('')
  console.log('Verified commitment')
  console.log(`  model       ${commitment.model_id} ${commitment.version}`)
  console.log(`  scheme      ${commitment.scheme}`)
  console.log(`  vk digest   ${commitment.vk_digest}`)
  console.log(`  transcript  ${commitment.transcript_digest}`)
  console.log(`  burn        ${commitment.burn_digest}`)
  console.log(`  signer      ${commitment.signer}`)
  console.log(`  published   ${new Date(newest.created_at * 1000).toISOString()}`)
  console.log('')
  console.log('Verify an inference proof against this digest with:')
  console.log(`  tvc verify --setup <dir> --digest ${commitment.vk_digest}`)

  if (events.length > 1) {
    const distinct = new Set(events.map((event) => tagValue(event, 'vk')))
    if (distinct.size > 1) {
      console.log('')
      console.log(`WARNING: relays served ${distinct.size} different digests for this address.`)
      console.log('Kind 30200 is addressable, so a later event replaces an earlier one at the')
      console.log('same coordinate. Divergence here means either a legitimate re-ceremony or an')
      console.log('attempted silent swap. Pin the digest out of band before trusting it.')
    }
  }

  return 0
}

main()
  .then((code) => {
    process.exitCode = code
  })
  .catch((error: unknown) => {
    console.error(`error: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  })
__W_TVC_FILE_22__

echo "  nostr-bridge/src/bridge.test.ts"
cat > 'nostr-bridge/src/bridge.test.ts' <<'__W_TVC_FILE_23__'
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'

import { COMMITMENT_KIND, CommitmentError, parseCommitment } from './commitment.ts'
import { buildEventTemplate, coordinatesFor, signEvent, tagValue } from './event.ts'

const VALID = {
  protocol: 'w-tvc/1',
  kind: 30200,
  address: 'acme-llm-7b:2026.09',
  model_id: 'acme-llm-7b',
  version: '2026.09',
  scheme: 'groth16-bn254',
  vk_digest: 'a'.repeat(64),
  transcript_digest: 'b'.repeat(64),
  burn_digest: 'c'.repeat(64),
  signer: 'd'.repeat(64),
  signature: 'e'.repeat(128),
}

test('accepts a well formed commitment', () => {
  const parsed = parseCommitment(VALID)
  assert.equal(parsed.model_id, 'acme-llm-7b')
  assert.equal(parsed.kind, COMMITMENT_KIND)
})

test('rejects an unknown protocol version', () => {
  assert.throws(() => parseCommitment({ ...VALID, protocol: 'w-tvc/2' }), CommitmentError)
})

test('rejects an unknown event kind', () => {
  assert.throws(() => parseCommitment({ ...VALID, kind: 1 }), CommitmentError)
})

test('rejects uppercase and short digests', () => {
  assert.throws(() => parseCommitment({ ...VALID, vk_digest: 'A'.repeat(64) }), CommitmentError)
  assert.throws(() => parseCommitment({ ...VALID, vk_digest: 'a'.repeat(63) }), CommitmentError)
})

test('rejects an address that disagrees with model and version', () => {
  assert.throws(() => parseCommitment({ ...VALID, address: 'other:2026.09' }), CommitmentError)
})

test('event carries the digest in both a tag and its content', () => {
  const template = buildEventTemplate(parseCommitment(VALID), 1789000000)
  assert.equal(template.kind, COMMITMENT_KIND)
  assert.equal(tagValue(template, 'vk'), VALID.vk_digest)
  assert.equal(tagValue(template, 'd'), VALID.address)
  assert.equal(JSON.parse(template.content).vk_digest, VALID.vk_digest)
})

test('signed event verifies and is addressable', () => {
  const secretKey = generateSecretKey()
  const commitment = parseCommitment(VALID)
  const event = signEvent(commitment, secretKey, 1789000000)

  assert.ok(verifyEvent(event))
  assert.equal(event.pubkey, getPublicKey(secretKey))
  assert.equal(event.created_at, 1789000000)
  assert.equal(
    coordinatesFor(commitment, event.pubkey),
    `${COMMITMENT_KIND}:${event.pubkey}:${VALID.address}`,
  )
})

test('pinned created_at makes the event id reproducible', () => {
  const secretKey = generateSecretKey()
  const commitment = parseCommitment(VALID)
  const first = signEvent(commitment, secretKey, 1789000000)
  const second = signEvent(commitment, secretKey, 1789000000)
  assert.equal(first.id, second.id)
})
__W_TVC_FILE_23__

echo ""
echo "==> Initialising git repository"
git init -q -b main
git add -A
git -c user.useConfigOnly=false commit -q -m "feat: initial scaffolding for W-TVC Protocol architecture"
echo "  committed $(git rev-list --count HEAD) revision as $(git rev-parse --short HEAD)"

echo ""
echo "==> Verifying the tree builds"
if command -v cargo >/dev/null 2>&1; then
  cargo test --workspace --quiet && echo "  rust: tests pass"
else
  echo "  rust: cargo not found, skipping"
fi
if command -v npm >/dev/null 2>&1; then
  (cd nostr-bridge && npm install --silent && npm run typecheck --silent && npm test --silent) \
    && echo "  typescript: typecheck and tests pass"
else
  echo "  typescript: npm not found, skipping"
fi

cat <<"NEXT"

================================================================
 W-TVC Protocol scaffolded and committed.
================================================================

 Try it immediately:

   cargo run --release --bin tvc -- demo

 Publish to GitHub and start the 4-week commit trail:

   1. Create an empty public repository (no README, no .gitignore):

        gh repo create w-tvc-protocol --public --source=. --remote=origin

      ...or manually at https://github.com/new, then:

        git remote add origin git@github.com:<you>/w-tvc-protocol.git

   2. Push:

        git push -u origin main

 Before any real ceremony:

   export TVC_SECRET_KEY=$(openssl rand -hex 32)

 That key signs your parameter commitments AND your Nostr events. It is the
 identity wallets pin. It is git-ignored by every pattern in .gitignore, and
 it must never be committed. If it leaks, every commitment you ever signed
 becomes forgeable and you must re-run the ceremony under a new key.

================================================================
NEXT
