# The weight commitment (earlier work, still in the tree)

This is the README as it stood on 27 September 2026, before W-TVC was pointed at
reference transparency. It documents `tvc register`, `tvc verify` and the
quantised weight commitment `C` in `tvc-core/src/commitment.rs`. All of it still
builds and is still tested. The reference-transparency work does not use `C`: a
per-file SHA-256 manifest answers "which files ran" for any model size, while `C`
answers a narrower question (can one weight be opened against a commitment) at
about 120 bytes of memory per parameter.

The ledger now also holds signed documents (format v3) beside these
registrations; see `docs/spec.md`.

## The problem

"This is Llama-3.2-1B" is, today, a filename and a README.

Nothing connects a set of weights to a claim by a named party. A mirror can serve a smaller derived model under a flagship name. A fine-tune can be redistributed as the base model. An operator can quietly swap a cheaper checkpoint behind an API and bill for the flagship.

Those are two different problems and it matters which one you are solving.

**Open weights.** You can download `W`. What is missing is an artefact to check it against — a signed statement from a named party saying "this is what we shipped".

**Closed weights.** You will never have `W`. The lab has it and you do not trust the lab. No amount of hashing on your side helps, because you have nothing to hash. What you need is (a) the lab irrevocably on record for one specific model, and (b) a way to check that a served inference came from *that* model. (b) requires zero-knowledge proofs of inference, and **is not implemented here** — see the roadmap in the main README. (a) is.

The usual answer to both is to trust a hosting platform's account system. That works exactly as far as the platform's perimeter and not one step past it.

## The approach

Make the weights themselves the thing that is named, and let a **key** rather than a platform do the naming.

| Stage | What happens |
|---|---|
| **Commit** | Weight tensors are quantised to a field vector and reduced to a 32-byte commitment `C`. |
| **Attest** | The publishing lab signs `(publisher, model_id, version, C, timestamp)` with a BIP-340 Schnorr signature. |
| **Register** | The signed attestation is appended to a hash-chained, append-only ledger. |
| **Verify** | Depends on which problem you have — see below. |

### What "verify" means in each case

| | Open weights | Closed weights |
|---|---|---|
| Check the signature against a pinned key | ✅ | ✅ |
| Recompute `C` from `W` and compare | ✅ | ✖ you have no `W` |
| Open individual weights against `C` | ✅ | only the lab can produce these |
| Bind a **served inference** to `C` | n/a | ⏳ needs the proving layer |

For open weights that is a complete story. For closed weights what you get today is **non-repudiation and consistency, not correctness**: the lab is on record for a specific `C`, and once the proving layer exists every inference must prove against that same `C`, so they cannot show one model to benchmarkers and serve another to customers. Nothing here establishes that the committed weights are any good, and nothing can.

### The dual commitment

Because of that gap, a registration binds **two** commitments under one signature:

```
C = tagged_hash( hash_commitment ‖ proof_commitment? ‖ length ‖ scale ‖ manifest )
```

- **`hash_commitment`** — a SHA-256 Merkle root. Always present. Anyone holding the weights recomputes it on a laptop, no trusted setup.
- **`proof_commitment`** — optional, the proving system's own commitment (a KZG `G1` point, a Poseidon root). Present once a proving system is chosen.

The second exists because a hash tree is the wrong object to check *inside* a circuit. Verifying a SHA-256 Merkle root over `n` weights costs roughly `2n` compressions at ~25–30k constraints each: for a billion-parameter model that is ~5×10¹³ constraints, several orders of magnitude past feasible. Poseidon cuts it ~100× and is still infeasible. The workable answer is for the weight commitment to *be* the commitment the proving system already produces for its witness columns, where binding costs almost nothing.

Both are folded into `C` and therefore covered by one signature — so the fast public identity and the in-circuit identity cannot drift apart. A publisher who signed for open weights cannot silently acquire a circuit identity later; that changes `C` and the signature stops verifying.

**A trap this creates.** `C` commits to weights quantised at a declared scale. A proof built against `proof_commitment` is a proof about the *quantised* vector — so if the deployed model serves `bf16` while the commitment is at `2^-16`, the proof is about different arithmetic than the thing answering requests. For closed weights the scale has to match the inference arithmetic, not the storage format.


## Quick start

The whole registration flow as library calls (simulate a model, commit, sign,
register, verify, open one weight, reject a one-weight substitution):

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

# 3b. For a closed model, bind the proving system's commitment under the same
#     signature. It must be supplied now — attaching one later changes C and
#     invalidates the signature, which is the intended behaviour.
cargo run --bin tvc -- register \
  --weights model.safetensors \
  --model-id acme/closed-model \
  --version 1.0.0 \
  --registry registry.jsonl \
  --proof-scheme kzg-bn254/v1 \
  --proof-commitment <hex>
```

### Verifying as a consumer

```bash
# Signature only: proves somebody signed this claim.
cargo run --bin tvc -- verify --model-id meta-llama/Llama-3.2-1B --registry registry.jsonl

# Open weights: pin the publisher and re-derive C from the weights on disk.
cargo run --bin tvc -- verify \
  --model-id meta-llama/Llama-3.2-1B \
  --registry registry.jsonl \
  --publisher <publisher public key> \
  --weights model.safetensors

# Closed weights: no weights to check, so report the circuit identity a proof
# would have to be verified against.
cargo run --bin tvc -- verify \
  --model-id meta-llama/Llama-3.2-1B \
  --registry registry.jsonl \
  --publisher <publisher public key> \
  --zk

# Re-derive every digest in the ledger and print its head.
cargo run --bin tvc -- audit --registry registry.jsonl
```

Every verification failure exits non-zero with a message naming what failed, so this works in a build gate.

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
| `tvc-cli/src/anchor.rs` | Submits the ledger head to a public OpenTimestamps calendar over HTTPS, and reports what a stored proof establishes without any further network call. |

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


## Threat model

**What a registration establishes.** One lab, holding one key, asserted that a named model version has weight commitment `C` at a claimed time. The registry refuses to store an attestation whose signature does not verify, so every record in a well-formed ledger is signed by the key it names.

**What it does not establish.**

- **Name ownership.** Two publishers can register the same `model_id` under different keys, exactly as two people can claim a username on two different servers. A registry cannot adjudicate this. Consumers resolve it by *pinning a key* — `verify_model_registration_by` — not by trusting the registry's ordering. There is an integration test asserting that a bare signature check passes for a rival's registration, because that is precisely why a bare check is not enough.
- **Weight quality.** `C` says which weights, not whether they are any good.
- **That a served inference used the committed weights.** This is the closed-weights gap and it is not closed here. `proof_commitment` is the hook for it; the circuit that would use it does not exist in this tree.
- **Timestamps.** The registry has no way to check a publisher's clock and does not pretend to. The timestamp is part of what was signed, so it is exactly as trustworthy as the key that signed it.
- **Rollback.** Truncating the ledger yields a shorter but internally valid history. This is caught by holding an earlier head, not by the chain itself — there is a test pinning that limitation in place. `tvc anchor` (see "Why Bitcoin" in the main README) is how that earlier head stops depending on a human's memory, once the calendar's commitment is upgraded to a Bitcoin attestation.
- **Anything in a ledger line this build does not recognise.** Unknown JSON fields are ignored so that a record written by a later version still opens here, and they are covered by neither the digest nor the signature. They are inert by construction and nothing should read them. An unknown *format version*, by contrast, is a hard stop: a reader that cannot reproduce a digest cannot honestly call the record verified.

**The bound quantisation puts on the claim.** Rounding to a fixed scale means two *different* models commit to the same `C` if they differ by less than half a step. At the default of 16 fractional bits the step is `2^-16 ≈ 1.5e-5`.

This cuts both ways, and the direction is easy to get backwards. The step is far **finer** than `bf16` precision (ULP ≈ `7.8e-3` near 1.0), so quantisation does **not** make `C` stable across dtype re-encoding — an `f32` checkpoint re-saved as `bf16` moves by hundreds of steps and commits to a different `C`. What the scale absorbs is only sub-step noise, such as the last-bit differences between two equivalent `f32` computations.

Whether that is right depends on what you want `C` to name. Committing to the weights *as stored* is the defensible default — a `bf16` copy is a different artefact — but a publisher shipping the same model in several dtypes must register each one. The scale is committed inside `C`, so a verifier can always see which claim was made.

