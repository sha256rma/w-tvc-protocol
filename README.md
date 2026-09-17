# W-TVC Protocol

**Verifiable Model Identity** — bind a set of AI model weights to the identity of the lab that published them, so anyone holding a copy can check whether it is the model its publisher attested to.

Built for **Bitshala BOSS Battle** · Tracks: **Machine Money** × **Freedom Stack**

```
Ship code. Beat the boss.
```

This repository currently implements the **model setup and public registry layer**. The zkML circuit and proving layer is future work; see [Roadmap](#roadmap).

---

## The problem

"This is Llama-3.2-1B" is, today, a filename and a README.

Nothing connects a set of weights to a claim by a named party. A mirror can serve a 1B distillation under a 70B name. A fine-tune can be redistributed as the base model. A provider can quietly swap a cheaper checkpoint behind an API and bill for the flagship. A consumer downloading weights has no way to tell any of this, because there is no artefact to check against.

The usual answer is to trust a hosting platform's account system. That works exactly as far as the platform's perimeter and not one step past it — it says nothing about the copy on your disk, the copy on a mirror, or the copy behind someone's inference endpoint.

## The approach

Make the weights themselves the thing that is named, and let a **key** rather than a platform do the naming.

| Stage | What happens |
|---|---|
| **Commit** | Weight tensors are quantised to a field vector and reduced to a 32-byte commitment `C`. |
| **Attest** | The publishing lab signs `(model_id, version, C, timestamp)` with a BIP-340 Schnorr signature. |
| **Register** | The signed attestation is appended to a hash-chained, append-only ledger. |
| **Verify** | Anyone recomputes `C` from weights in hand and checks the signature against a pinned publisher key. |

Verification needs the ledger, the weights, and the publisher's 32-byte public key. It does not need the publisher to be online, a certificate chain, or a trusted third party.

---

## Quick start

```bash
cargo test          # 87 tests
cargo run --bin tvc -- demo
```

`tvc demo` runs the whole flow into `demo-out/`: it simulates a model, commits to its weights, signs the registration, appends it to a ledger, verifies the entry, opens a single weight against the commitment, then substitutes one weight out of ninety-six and confirms the registry rejects it.

For the same flow as library calls rather than CLI output:

```bash
cargo run --example register_model
```

### Registering a real model

```bash
# 1. Generate a publisher identity. The secret key is printed once, never stored.
cargo run --bin tvc -- keygen
export TVC_SECRET_KEY=<the secret key it printed>

# 2. Inspect a commitment without registering anything.
cargo run --bin tvc -- commit --weights model.safetensors

# 3. Commit, sign, and append to the registry.
cargo run --bin tvc -- register \
  --weights model.safetensors \
  --model-id meta-llama/Llama-3.2-1B \
  --version 1.0.0 \
  --registry registry.jsonl
```

### Verifying as a consumer

```bash
# Signature only: proves somebody signed this claim.
cargo run --bin tvc -- verify --model-id meta-llama/Llama-3.2-1B --registry registry.jsonl

# Pin the publisher and re-derive C from the weights on disk. This is the real check.
cargo run --bin tvc -- verify \
  --model-id meta-llama/Llama-3.2-1B \
  --registry registry.jsonl \
  --publisher <publisher public key> \
  --weights model.safetensors

# Re-derive every digest in the ledger and print its head.
cargo run --bin tvc -- audit --registry registry.jsonl
```

Every verification failure exits non-zero with a message naming what failed, so this works in a build gate.

---

## Architecture

```
  model.safetensors
         │
         ▼
  ┌──────────────┐   quantise to fixed point, map into BN254's scalar field
  │ commitment   │
  │  scheme      │   VectorCommitment over a bare [FieldElement]
  │  layer       │   → scheme commitment (merkle root + length)
  │  ─────────   │
  │  protocol    │   bind scheme ‖ scheme_commitment ‖ length
  │  layer       │        ‖ fractional_bits ‖ manifest_digest
  └──────┬───────┘
         │  C  (32 bytes, always — it is a tagged hash)
         ▼
  ┌──────────────┐   payload = (model_id, version, C, timestamp)
  │ signer       │   BIP-340 Schnorr over secp256k1
  └──────┬───────┘
         │  (payload, signature, publisher pubkey)
         ▼
  ┌──────────────┐   append-only JSON Lines, one record per line
  │ registry     │   each record digests the one before it
  └──────────────┘
```

| Module | Role |
|---|---|
| `tvc-core/src/commitment.rs` | Weight loading, quantisation, `C = Commit(W)`, Merkle openings. |
| `tvc-core/src/signer.rs` | Publisher keypairs, registration payload, BIP-340 attestations. |
| `tvc-core/src/registry.rs` | The append-only, hash-chained public ledger. |
| `tvc-core/src/digest.rs` | BIP-340 tagged hashing and domain separation. |
| `tvc-core/src/hex.rs` | Strict lowercase hex codec used on every boundary. |
| `tvc-core/src/error.rs` | The error taxonomy. |
| `tvc-cli/src/main.rs` | The `tvc` command line; the only place randomness and secrets enter. |

### Why the commitment is split into two layers

`VectorCommitment` commits to a bare `&[FieldElement]` and knows nothing about
tensors. The protocol binding — scheme tag, element count, quantisation scale,
tensor manifest — lives above it in `WeightCommitment`.

The payoff is that **`C` is always 32 bytes whatever the scheme**, because it is
always a tagged hash *over* the scheme's commitment rather than the scheme's
commitment itself. A KZG or Pedersen backend has a group element where the Merkle
root is, and `signer.rs` and `registry.rs` never notice. The tensor manifest also
correctly leaves the trait: a polynomial commitment has no notion of a tensor.

### Why the commitment is a three-stage pipeline

```
  tensors ──quantise──> field vector ──commit──> scheme commitment ──bind──> C
```

**Quantise** throws away what must not matter. Committing to `f32` bit patterns would make the commitment hostage to them: `-0.0` and `0.0` are the same weight but different bytes, as are two NaN payloads. Fixed-point integers are also the representation an arithmetic circuit will want later, which is why the weight vector lives in BN254's scalar field — the commitment made today is over the same vector a circuit will read tomorrow.

**Commit** makes the commitment *openable*. A publisher can prove `W[i] = v` against a registered `C` without shipping the model. Openings are canonical: direction comes from the index and the step count is recomputed from the committed length, so there is exactly one accepting proof of any given fact, and a path with a step inserted or removed is rejected on shape rather than hashed into some other root.

**Bind** closes the gaps the root alone leaves. `C` is a tagged hash over the tree root *plus* the element count, the fractional-bit scale, and a digest of the tensor manifest. Without the manifest, a `[2, 3]` tensor and a `[3, 2]` tensor holding the same numbers would commit identically.

Tensors are concatenated in **lexicographic name order**, not file order — file order is an artefact of whatever wrote the checkpoint, so sorting is what lets two honest publishers of the same model reach the same `C`.

### Why BIP-340 Schnorr rather than ECDSA

Three reasons, in order of weight:

- **Non-malleable.** ECDSA admits a second valid signature for the same message and key by negating `s`. In an append-only registry that means one attestation can be republished as two distinct-looking records.
- **Canonical 64-byte encoding.** ECDSA's DER is a parsing minefield with a long history of signature-mutation bugs.
- **Linear.** A consortium of labs can later co-sign one registration as a single aggregate key with no change to what a verifier does.

### Why a hash-chained flat file rather than SQLite

Append-only is a *policy* that no filesystem enforces. A line-delimited file has no in-place update operation, so the ordinary way to change history is to rewrite the file — a visible act — rather than `UPDATE ... WHERE`, an invisible one. It also diffs, greps, tails and replicates with tools an auditor already has.

Each record carries the digest of the record before it. Editing, reordering or deleting any record changes every digest after it, and `verify_chain` reports the exact line where the divergence starts. This does not make tampering impossible — a determined editor can recompute the whole chain. It makes tampering **detectable by anyone who saw an earlier head**, which is what turns a file into a ledger.

SQLite is the right answer once this registry serves concurrent writers. It is the wrong answer today: it would put a mutable B-tree under an append-only claim.

Until then a second writer is **refused rather than tolerated**. An exclusive advisory lock serialises the append, and under that lock the file's length is compared against what the handle last read. The length check is the part that matters: a record's sequence number and `previous` digest come from state read earlier, so the lock alone would not help — two processes can each read a ledger of N records, queue on the lock, and both append at sequence N. Six concurrent `tvc register` processes against one ledger produce two successes and four clean failures, not six lines and a forked chain.

---

## What is real, and what is scaffolding

Honesty about scope is load-bearing for a protocol that asks to be trusted.

**Real, and exercised by the test suite.**

- BIP-340 Schnorr signing and verification over secp256k1.
- Tagged, length-prefixed, domain-separated hashing, checked against the BIP-340 reference construction.
- safetensors parsing with full range validation — truncated files, oversized header lengths, and shapes that disagree with their byte ranges are all rejected rather than read short.
- Deterministic fixed-point quantisation into the BN254 scalar field, including the negative-value mapping and the `2^53` exact-integer bound.
- The SHA-256 Merkle vector commitment and its canonical openings, including rejection of an opening moved to another index, shortened, or padded with an extra step.
- The ledger's hash chain, including detection of edited, deleted and reordered records, of an unknown format version, and of an append from a stale handle.

**Scaffolding, with a documented upgrade path.**

- `MerkleVectorCommitment` is a hash-based vector commitment, not a succinct one. Openings are `O(log n)` rather than constant-size. `VectorCommitment` is the seam where KZG or Pedersen goes; nothing outside `commitment.rs` sees a tree.
- The tree hash is SHA-256, which is bitwise and costs tens of thousands of constraints per compression to verify inside an arithmetic circuit. The BN254 field encoding means the vector needs no re-encoding when a circuit arrives; it does not by itself make anything circuit-efficient. A field-native hash (Poseidon) is the change that would, and it is deferred until the proving system is chosen.
- The tree is held in memory, so this phase targets models in the tens of millions of parameters. `MerkleProver` keeps the levels so repeated openings are `O(log n)`, but streaming and memory-mapped trees are what lift the ceiling — and they change no interface here.
- **ONNX ingestion is not implemented.** `Tensor` is the interface a loader produces, and only safetensors has one today. ONNX is protobuf, and a protobuf parser is a dependency this phase deliberately does not take.
- The registry is a local file. Replication, and publishing the head digest somewhere a consumer can independently see it, are out of scope for this phase.
- Single-writer is the supported mode. Concurrent writers are detected and refused, not merged.

**Not in this repository at all.** The arithmetic circuit and the proving system.

---

## Threat model

**What a registration establishes.** One lab, holding one key, asserted that a named model version has weight commitment `C` at a claimed time. The registry refuses to store an attestation whose signature does not verify, so every record in a well-formed ledger is signed by the key it names.

**What it does not establish.**

- **Name ownership.** Two publishers can register the same `model_id` under different keys, exactly as two people can claim a username on two different servers. A registry cannot adjudicate this. Consumers resolve it by *pinning a key* — `verify_model_registration_by` — not by trusting the registry's ordering. There is an integration test asserting that a bare signature check passes for a rival's registration, because that is precisely why a bare check is not enough.
- **Weight quality.** `C` says which weights, not whether they are any good.
- **Timestamps.** The registry has no way to check a publisher's clock and does not pretend to. The timestamp is part of what was signed, so it is exactly as trustworthy as the key that signed it.
- **Rollback.** Truncating the ledger yields a shorter but internally valid history. This is caught by holding an earlier head, not by the chain itself — there is a test pinning that limitation in place.
- **Anything in a ledger line this build does not recognise.** Unknown JSON fields are ignored so that a record written by a later version still opens here, and they are covered by neither the digest nor the signature. They are inert by construction and nothing should read them. An unknown *format version*, by contrast, is a hard stop: a reader that cannot reproduce a digest cannot honestly call the record verified.

**The bound quantisation puts on the claim.** Rounding to a fixed scale means two *different* models commit to the same `C` if they differ by less than half a step. At the default of 16 fractional bits the step is `2^-16 ≈ 1.5e-5`.

This cuts both ways, and the direction is easy to get backwards. The step is far **finer** than `bf16` precision (ULP ≈ `7.8e-3` near 1.0), so quantisation does **not** make `C` stable across dtype re-encoding — an `f32` checkpoint re-saved as `bf16` moves by hundreds of steps and commits to a different `C`. What the scale absorbs is only sub-step noise, such as the last-bit differences between two equivalent `f32` computations.

Whether that is right depends on what you want `C` to name. Committing to the weights *as stored* is the defensible default — a `bf16` copy is a different artefact — but a publisher shipping the same model in several dtypes must register each one. The scale is committed inside `C`, so a verifier can always see which claim was made.

---

## Dependencies

Six crates, each load-bearing:

| Crate | Why |
|---|---|
| `secp256k1`, `bitcoin_hashes` | Consensus-grade primitives; hand-rolling either would be reckless. |
| `zeroize` | Signing keys must not linger in freed memory. |
| `serde`, `serde_json` | The ledger and the safetensors header are both JSON read back from untrusted disk. A parser on that boundary is exactly what should not be homegrown. |
| `fs2` | Advisory file locking. A sidecar lockfile is orphaned by a crash or a `SIGKILL` and then needs deleting by hand; an OS lock lives on the file descriptor and the kernel releases it however the process dies. Raw `flock` is not an option because `tvc-core` forbids unsafe code. |

Hex stays in-tree (`tvc_core::hex`): forty auditable lines, and every digest a verifier acts on passes through it. The CLI adds `clap` and `getrandom`.

---

## Repository layout

```
.
├── Cargo.toml                       workspace, dependency policy
├── tvc-core/
│   ├── src/
│   │   ├── lib.rs                   crate docs, end-to-end doctest
│   │   ├── commitment.rs            weight loading, quantisation, C = Commit(W)
│   │   ├── signer.rs                publisher keys, payload, BIP-340 attestations
│   │   ├── registry.rs              append-only hash-chained ledger
│   │   ├── digest.rs                tagged hashing, domain separation
│   │   ├── hex.rs                   strict lowercase hex codec
│   │   └── error.rs                 error taxonomy
│   ├── examples/register_model.rs   end-to-end walkthrough as library calls
│   └── tests/end_to_end.rs          integration tests
├── tvc-cli/src/main.rs              the `tvc` binary
├── .env.example                     TVC_SECRET_KEY template
└── LICENSE
```

---

## Key handling

`tvc-core` has no entropy source and no environment access by design. The CLI is the one place both appear, so the trust boundary is a file you can read rather than a library default you have to take on faith.

- Randomness comes from the operating system via `getrandom`, for key generation and for BIP-340 auxiliary randomness.
- The signing key is read from `TVC_SECRET_KEY`, never from a flag. Command-line arguments are visible in `ps` output and land in shell history; an environment variable is merely bad rather than broadcast.
- `PublisherKeypair` holds its scalar in a `Zeroizing` buffer, is not `Clone`, is not serialisable, and its `Debug` prints `<redacted>`. The only way out is `expose_secret_hex`, whose name is the warning.

---

## Roadmap

1. **This phase — setup and registry.** Weight commitments, publisher attestations, append-only ledger. Done.
2. **Openings at scale.** Swap `MerkleVectorCommitment` for KZG behind the existing `VectorCommitment` trait, for constant-size and circuit-friendly openings.
3. **Scale.** Streaming leaf construction and a memory-mapped tree, to lift the in-memory ceiling past tens of millions of parameters.
4. **ONNX ingestion.** A second loader producing `Tensor`, so the commitment scheme is unchanged.
5. **Circuit registration.** Register the arithmetic circuit for a model alongside its weights, committing to the relation as well as the parameters. This is also when the tree hash should move to Poseidon.
6. **Runtime proofs.** Prove an inference was served by the committed weights. This is where the commitment made in step 1 gets used — and why the weight vector already lives in BN254's scalar field.
7. **Distribution.** Replicate the ledger and publish the head digest somewhere a consumer can independently see it — a CT-style signed tree head, anchored periodically to a public chain.

---

## License

MIT. See [LICENSE](LICENSE).
