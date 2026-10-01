# W-TVC

W-TVC lets a model checker prove what it ran. Into a signed, append-only log it publishes the weight files a reference run used, the settings it ran with, and commitments to the secret prompts and to the outputs. Anyone can check the log without trusting the checker, and its head is timestamped on Bitcoin.

Built for **Bitshala BOSS Battle** · Tracks: **Machine Money** × **Freedom Stack**

```
Ship code. Beat the boss.
```

## The problem

Providers sell access to open models by name, and some serve a cheaper model or a 4-bit copy under that name. On 5 May 2026 a strict client caught a private-inference gateway answering as `Qwen/Qwen3.5-122B-A10B` while billing for `deepseek-ai/DeepSeek-V3.1` ([awesome-private-inference](https://github.com/amiller/awesome-private-inference)).

The way to catch this from outside is to compare the endpoint with reference answers produced by running the real model yourself. That's what our checking service, [authenticated.si](https://authenticated.si) (SPOT), does. But every verdict then rests on the reference, and a provider flagged as "likely swapped" will ask four fair questions:

1. Which weights did you run?
2. How did you run them?
3. Which prompts did you use, and what did your model say?
4. Did you change your reference after you saw my output?

Today the honest answer to all four is "trust us". W-TVC replaces that with things a third party can recompute.

## What W-TVC publishes

A reference is a chain of four signed documents. Each one names the one before it by SHA-256.

```
weights-manifest/v1   every file the reference loaded: path, size, sha256       (public)
       ▲
reference-setup/v1    engine, version, dtype, hardware, decoding settings,
                      chat-template and system-prompt digests                   (public, self-reported)
       ▲
reference-run/v1      salted Merkle roots of the prompts and of the outputs,
                      sample counts, determinism, measured bands                (roots public, items secret)
       ▲
profile/v1            one handbook entry: model, version, maturity
```

The signed claims go in an append-only, hash-chained ledger (`registry.jsonl`). The documents sit beside it as `objects/<sha256>.json`, so `sha256sum` on any of them prints its own file name. The ledger head is submitted to the OpenTimestamps calendars and ends up in a Bitcoin block.

| The provider asks | What answers it | How anyone checks |
|---|---|---|
| Which weights? | the weights manifest | `tvc check-hf` compares it with the SHA-256 Hugging Face publishes for every large file, so 988 MB of weights are checked without downloading them. `tvc verify-dir` re-hashes a local copy. |
| How were they run? | the setup record | It can't be changed after publication, and it's specific enough to re-run. It's the publisher's own description, and it says so. |
| Which prompts, which answers? | the run record's two roots | When a verdict is disputed, `tvc reveal` opens the prompts in question with a Merkle proof. `tvc verify-reveal` confirms they were in the set at publication, at that position. |
| Changed afterwards? | ledger order and the Bitcoin timestamp | A record can only cite records already in the ledger, and the anchored head dates the whole ledger up to that point. |

The prompts stay secret on purpose. If they were public, a provider could recognise them and send only those to the real model. So SPOT commits to them first and reveals them one at a time, when there's a reason to. I think this is the one place where publishing everything would make the system easier to cheat.

## Try it

Five commands, from the repository root. None of them needs a GPU, and only the last two touch the network.

```bash
cargo test --workspace

# The whole story offline, ending with five cheating attempts that get refused.
cargo run --release --bin tvc -- demo

# Check the real reference in reference/ as an outsider would.
cargo run --release --bin tvc -- verify-reference --registry reference/registry.jsonl \
  --profile dc7d054fbd75b6c74055ab3e6c074c5a28e3606296e0a3afce05372a92616374 \
  --publisher 8f738e4f8e4b3ce2b820dcc9cea88635f0992a56f23eccbc4b5a8d968db421cd

# Compare the published Qwen manifest with Hugging Face, without downloading the weights.
cargo run --release --bin tvc -- check-hf \
  --manifest reference/objects/3f976cbf5f3e4ad9b15f23c1a16987851be036b2179d1025e983f4c68b2cf82c.json

# Ask the calendar whether the ledger head has reached a Bitcoin block yet.
cargo run --release --bin tvc -- verify-anchor --registry reference/registry.jsonl
```

`verify-reference` prints nine named checks and exits non-zero on the first class of failure: 2 ledger, 3 signature, 4 document, 5 weights on disk, 6 anchor. Add `--json` for machine output. [`docs/verify-yourself.md`](docs/verify-yourself.md) walks through every claim with commands you can paste.

## A real reference: Qwen2.5-0.5B-Instruct

`reference/` holds a ledger built on 2 October 2026 (IST) under a demo publisher key, `8f738e4f`. It isn't SPOT's production key. The ledger head `0fd05073` was submitted to the OpenTimestamps calendar at 2026-10-01 19:51 UTC.

There are two profiles, because there are two artefacts:

- **Skeleton** (`0a372de8`). The Hugging Face safetensors at commit `7ae557604adf`. All eight files match the hub. `model.safetensors` matches the hub's LFS hash `fdf756fa` without being downloaded. There are no runs, because this machine has no PyTorch build for its Intel CPU and Python 3.14, so it can't run safetensors. The handbook calls a profile like this a skeleton.
- **Working** (`dc7d054f`). Ollama's `qwen2.5:0.5b` build of the same model, a 4-bit `Q4_K_M` GGUF, run with Ollama 0.24.0 on an Intel Core i9-9980HK with no GPU. Twelve prompts, three samples each at temperature 0 and seed 42. All twelve reproduced byte for byte across samples. The bands hold only measured values: Ollama counted 195 prompt tokens over the four tokenizer prompts and 554 over all twelve, identical on every sample.

The two builds have different manifests (`3f976cbf` and `1fc98d37`), as they should. That gap is exactly the "quantised copy" case SPOT exists to catch. The setup record also pins Ollama's default system prompt for this tag ("You are Qwen, created by Alibaba Cloud. You are a helpful assistant."), which a provider could otherwise change silently.

The reference also records the model's wrong answers. It says the capital of Australia is Sydney, and that 4821 × 37 is 159674 (it's 178377). A reference is what the real model says, not the right answer. An endpoint selling this model that gets those right is serving something else. Both prompts are opened, with proofs, in [`reference/reveals/`](reference/reveals/). The other ten stay sealed.

The harness that produced the run is [`reference/run_ollama_reference.py`](reference/run_ollama_reference.py). It uses the standard library only.

## What a check proves, and what it doesn't

A passing `verify-reference` means:
- every document in the chain is signed by the key you pinned;
- each document's bytes hash to the digest that was signed;
- each document cites what its signed claim says it cites;
- every run used the weights the profile names;
- if you pass `--weights-dir`, the files on your disk are those weights, byte for byte;
- if anchored, the profile was in the ledger before the anchored head was timestamped.

It doesn't mean:
- **The setup ran as described.** The engine, version and GPU are the publisher's word. What's fixed is the description, which you can re-run.
- **The outputs came from the model.** They're what the publisher says the model said. On a pinned stack this run reproduced 12 of 12. Across GPUs and engines, greedy decoding drifts, so third-party re-runs are compared within bands, not byte for byte. A two-GPU determinism test is on the roadmap before anyone should claim more.
- **The Bitcoin block is real.** `verify-anchor` reads the proof and prints the block height and the merkle root it claims. It doesn't fetch blocks. You finish the check on any block explorer.
- **The key is SPOT's.** A key is 32 bytes. Pin it from somewhere you already trust.

## Why Bitcoin

The only thing the timestamp is for is the fourth question: did SPOT change its reference after seeing a provider's output. Signatures and hashes can't answer that, because SPOT holds the key and could sign a new reference with any date it likes. It takes a party SPOT doesn't control to say "this existed by then". OpenTimestamps puts the commitment in a Bitcoin block for free, with no account. Sigstore's Rekor log would also work, and the `Anchor` trait in `tvc-cli/src/anchor.rs` is where it would go.

The upgrade from "pending" to "in a block" takes a few hours. `tvc verify-anchor` asks the calendar for it and stores it when it's ready. The tool only contacts calendars on the reference client's default list, over HTTPS, because the URL comes out of a file.

## How it fits with secure-hardware inference

Confidential-inference providers run models inside Intel TDX or AMD SEV enclaves and publish attestations. [awesome-private-inference](https://github.com/amiller/awesome-private-inference) re-checks them daily. Its findings are the clearest case for W-TVC: the weak point is "which model". For Chutes, "`model_name`/`revision` are never bound to the quote". For RedPill/Phala, model-weight provenance is listed as unknown. Tinfoil pins weights by a dm-verity root hash, and NEAR pins a Hugging Face revision.

W-TVC isn't an enclave and doesn't replace one. It does two things those systems don't:
- It gives "which weights" a publisher-signed, provider-independent name that an attestation could cite.
- It applies the same discipline to the checker. If SPOT one day runs its references inside an attested GPU with the weights measured, the records stay the same, and the reference outputs become evidence instead of a statement.

## How we got here

This repository changed direction twice, and the history is in `git log`.

In week 1 (14 to 16 September) it was a Groth16 ceremony meant to prove which model served each inference, published over Nostr. That can't scale: verifying a SHA-256 Merkle root of the weights inside a circuit costs roughly 5×10¹³ constraints for a billion parameters. So it was deleted.

In week 2 (18 September) it became a registry. A publisher signs a 32-byte commitment to quantised weights, recorded in a hash-chained ledger. Reading our own README, we found it promised to catch API model swaps while requiring the verifier to hold the weights. That gap led to the dual commitment. That work is still here and still tested. It's documented in [`docs/weight-commitment.md`](docs/weight-commitment.md).

Week 3 turned it around. The party that most needs to prove what it ran is the checker, so W-TVC now publishes SPOT's references. The quantised commitment isn't used for that: a file manifest answers "which files" for any model size.

## What's next

Roughly in order:

1. SPOT's reference harness emits these documents directly, with bands keyed by catalogue check id (PW-01, ID-06, BH-01 and so on).
2. A two-GPU determinism test on reference outputs before claiming third parties can reproduce them. Then a second, quantised fingerprint for logprobs, so ID-01 and QZ-01 bands survive cross-GPU noise.
3. Fiat-Shamir item selection in the check runner, so which committed prompts a check uses is derived from the commitment, the endpoint and the date. `tvc sample` already does the derivation.
4. Check results in the ledger, signed by the analyst. They'll most likely be recorded as raw signal values with the verdict on top, so a wrong call can be corrected without rewriting history.
5. Key management: an org key, analyst keys, key rotation records, and the public key published on authenticated.si.
6. References run inside a confidential GPU with the weights measured.

## Commands

| Command | What it does |
|---|---|
| `manifest` | Hash every file in a model directory into a weights manifest. |
| `verify-dir` | Check that a directory holds exactly the files a manifest lists. |
| `check-hf` | Compare a manifest with Hugging Face at its pinned commit. |
| `commit-items` | Commit to a JSONL file of secret items (prompts or outputs) with fresh salts. |
| `reveal`, `verify-reveal` | Open one committed item with its proof, and check it. |
| `sample` | Pick items from a committed set in a way nobody can steer. |
| `publish`, `show` | Sign a document into the ledger, and print one back. |
| `verify-reference` | Check a profile and everything it cites, check by check. |
| `anchor`, `verify-anchor` | Timestamp the ledger head, and follow the proof to a Bitcoin block. |
| `audit` | Re-derive every digest in the ledger and list its records. |
| `demo` | All of the above, offline, with the cheating attempts at the end. |
| `keygen`, `commit`, `register`, `get`, `verify` | The earlier weight-commitment flow; see `docs/weight-commitment.md`. |

The record formats, the canonical JSON rules, the item leaf and the signing domains are in [`docs/spec.md`](docs/spec.md).

## Repository layout

```
tvc-core/src/
  canonical.rs     canonical JSON and content digests
  manifest.rs      per-file weight manifests
  itemset.rs       salted item commitments, reveals, Fiat-Shamir selection
  documents.rs     the four reference kinds, and the object store
  registry.rs      the append-only ledger (model registrations v2, documents v3)
  signer.rs        BIP-340 keys, registrations, document claims
  commitment.rs    the quantised weight commitment and its Merkle tree
  digest.rs, hex.rs, error.rs
tvc-cli/src/
  main.rs          the tvc binary
  reference.rs     manifest, publish, reveal and verify-reference commands
  hf.rs            the Hugging Face comparison
  anchor.rs        OpenTimestamps submission, parsing and upgrade
reference/         a real ledger for Qwen2.5-0.5B-Instruct, and its harness
docs/              spec, verify-yourself walkthrough, demo script, earlier README
```

## Dependencies

Each one is justified in prose in the workspace `Cargo.toml`. `tvc-core` uses:
- `secp256k1` and `bitcoin_hashes` for signatures and hashes;
- `zeroize` for key hygiene;
- `serde` and `serde_json` for every JSON boundary;
- `fs2` for the ledger lock.

The CLI adds:
- `clap`, `getrandom`;
- `ureq` for the calendar and Hugging Face over HTTPS;
- `bitcoin_hashes` directly, for SHA-1 and RIPEMD-160 on proof paths.

The minimum Rust version is 1.85, which the locked `clap` requires. `tvc-core` keeps `unsafe_code = "forbid"` and `missing_docs = "deny"`.

## License

MIT. See [LICENSE](LICENSE).
