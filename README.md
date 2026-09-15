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
