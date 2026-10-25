# ModelCert

![ModelCert: pay only for the model you got](docs/img/cover.png)

ModelCert is an open protocol for paying for AI inference only when you got the model you paid for. It works like HTTPS certificates, for models:

- **Certificates.** Each provider gets a certificate for each model it serves. It holds while the provider keeps matching the real model on secret test questions mixed into its traffic. A provider that fails is revoked in public.
- **Receipts.** Every answer comes back with a receipt signed by the gateway. The receipt names the model and the provider that answered, and chains to that provider's certificate.
- **Settlement.** An agent pays per request over [x402](https://www.x402.org). The payment is held, and it settles only while the provider's certificate holds. If the provider is caught serving anything else, its held payments go back to the buyers.

Behind every certificate is a public reference: the official weights, sealed test questions, and thresholds set from honest setups of the same model. Anyone can add an honest setup. All of it is signed, kept in an append-only ledger and timestamped in Bitcoin, so anyone can recheck any receipt, certificate or verdict without trusting whoever issued it.

ModelCert was called W-TVC. The code still uses that name: the `tvc` command and the `tvc-core` crate. [authenticated.si](https://authenticated.si) runs SPOT, the first gateway built on it.

**What's real today:**
- the ledger, the reference and calibration documents, and the tools that verify them;
- the Qwen2.5-7B reference with two demo verdicts, anchored in Bitcoin blocks 969564 to 969658;
- GPU references for 14 open models in authenticated.si's private harness.

**Designed, not built yet:**
- provider certificates;
- receipts;
- x402 settlement;
- outside contributions to the honest set.

No real provider has been checked in this ledger.

A [10-minute walkthrough](docs/demo-walkthrough.md) runs every existing check from a fresh clone.

## Why this matters

![Same idea, new domain](docs/img/bitcoin-parallel.png)

Bitcoin removed the need to trust a bank to move money. Anyone can check the rules, and trust comes from verification instead of an institution. AI needs the same thing.

A few frontier labs decide which questions their models answer, and they see everything you send. Open models are the way out: anyone can run them, many independent providers host them, and you can switch whenever you like. But an open model is only as trustworthy as whoever serves it. On a marketplace like OpenRouter, a provider can sell you "DeepSeek" and serve a cheaper compressed copy, or a different model, and you can't tell.

ModelCert builds that trust the Bitcoin way:
- **Pay for proof.** Payments settle only for answers from providers that match the real model.
- **Verify, don't trust.** Every answer has a receipt you can recheck.
- **No new gatekeeper.** Every reference, threshold and verdict is signed and published, so anyone can check the checker.
- **Secret tests, public proof.** The questions stay secret so providers can't game them, but their fingerprints are fixed in public before any provider is tested.
- **An open definition of "honest".** The setups that decide what counts as normal come from many independent GPUs, not only the checker's.
- **Bitcoin as the clock.** Records are timestamped in Bitcoin, so nobody can quietly rewrite them later, including us.

## The problem

Providers sell access to open models by name, and some serve a cheaper model or a 4-bit copy under that name. On 5 May 2026 a strict client caught a private-inference gateway answering as `Qwen/Qwen3.5-122B-A10B` while billing for `deepseek-ai/DeepSeek-V3.1` ([awesome-private-inference](https://github.com/amiller/awesome-private-inference)).

The way to catch this from outside is to compare the endpoint with reference answers from running the real model yourself. That's what authenticated.si does. But every verdict then rests on the reference, and a flagged provider will ask five fair questions:

1. Which weights did you run?
2. How did you run them?
3. Which questions did you use, and what did your model say?
4. Did you change your reference after you saw my output?
5. My setup is honest but different from yours. Why should your setups define "normal"?

ModelCert answers the first four with things a third party can recompute. The open honest set is the answer to the fifth. And for buyers the answer arrives with every request: a receipt, and a payment that settles only if the provider holds up.

## How it works

![How ModelCert works](docs/img/protocol-flow.png)

```mermaid
sequenceDiagram
  participant A as Your agent
  participant G as Gateway (SPOT)
  participant P as Provider
  participant L as Public ledger
  A->>G: request
  G-->>A: 402 Payment Required, 0.002 USDC
  A->>G: request + x402 payment
  Note over G: payment held
  G->>P: request (provider certificate current)
  P-->>G: answer
  G-->>A: answer + signed receipt (model, provider, certificate, hashes)
  G->>L: receipt batch root
  alt certificate still holds
    G->>P: payment settles
  else provider fails a secret check
    G->>L: certificate revoked
    G-->>A: held payments refunded
  end
```

The receipt is the per-request piece, and the certificate is what makes it mean something. One answer on its own can't show which model wrote it. A provider's answers to secret test questions, compared with the real model over many requests, can. The receipt ties each paid answer to the certificate that covered it, so a later failed check reaches back to the payments still held.

![A receipt and its chain](docs/img/receipt.png)

| HTTPS | ModelCert |
| --- | --- |
| Root certificate | The reference: official weights by file hash, sealed questions, anchored in Bitcoin |
| Intermediate | The calibration: thresholds from honest setups of the same model |
| Site certificate | The provider certificate: this provider, this model, passing secret checks |
| TLS session | The receipt: this request, this answer, this payment |
| Certificate Transparency log | The ledger: every certificate, revocation and receipt batch, append-only |
| Revocation | A failed check revokes the certificate, and held payments go back |

## How a provider is checked

```mermaid
flowchart LR
  HF["Official weights<br/>Hugging Face"] --> REF["Reference run<br/>our GPU, secret questions"]
  REF --> RULER["The ruler<br/>every reference answer"]
  HON["Honest setups<br/>same weights, other engines,<br/>GPUs, settings"] --> MA["Mini-audits<br/>compare 20 answers per question<br/>with the ruler, 200 times"]
  FAKE["Known fakes<br/>FP8, 4-bit, smaller model,<br/>hidden prompt"] --> MA
  PROV["Provider endpoint"] --> MA
  RULER --> MA
  MA --> LINE["Threshold<br/>95% of honest mini-audits below"]
  MA --> VERDICT["Verdict<br/>altered if 90% or more of the<br/>provider's mini-audits are past it"]
  LINE --> VERDICT
  LINE & VERDICT --> LED[("Public ledger<br/>signed, timestamped in Bitcoin")]
```

- **The reference** decides what everything is measured against.
- **The honest setups** decide how much difference is normal. They use the same weights on different engines, engine versions, GPUs and options.
- **The known fakes** show what that threshold catches and what it misses. The calibration publishes both.
- **The provider** is only judged. It never moves the threshold.

A flag means the endpoint is outside everything honest setups produced. A pass means no detectable difference, which isn't proof the endpoint is genuine. The full walkthrough, with diagrams, is in [`docs/how-it-works.md`](docs/how-it-works.md).

## Latest results

From authenticated.si's private harness, October 2026, judged with 20 answers per question. These runs aren't in this ledger yet.

| Model | Honest setups that passed | Altered copies caught | Missed |
| --- | --- | --- | --- |
| Gemma-4-26B-A4B | 23 of 23 (vLLM 0.30 to 0.32, SGLang 0.5.21 and 0.5.22, A100 and H100) | 11 of 11: FP8 on both GPUs and engines, 4-bit, smaller model, thinking on, two hidden system prompts | none |
| Gemma-4-31B | 16 of 16 | 4 of 5: two model swaps, thinking on, Google's 4-bit | FP8 |
| Qwen3.6-35B-A3B | 13 of 13 | 5 of 7: uncensored copy, previous generation, AWQ 4-bit, system prompt, thinking on | GPTQ 4-bit, FP8 KV cache |

With 5 answers per question, FP8 and most 4-bit copies pass. The honest setups cover two engines and two GPU types. TensorRT-LLM, multi-GPU serving, B200 and AMD GPUs aren't covered yet, which is why the open honest set comes next.

## The open honest set

Today one party, authenticated.si, runs every honest setup. Contributions from anyone will work like this. Phase 1 is the first to build.

1. **Run a public battery.** Contributors run a public version of the tests on their own GPU, with the official weights, and sign the result with their own key. No secret question leaves authenticated.si.
2. **Reproduce on the secret battery.** A second party reruns the same setup on the secret questions:
    - **Phase 1:** a trusted runner replays the setup.
    - **Phase 2:** for hardware nobody can rent, we query the contributor's endpoint with a single-use slice of questions, which is then retired and published.
    - **Phase 3:** a confidential-computing GPU releases the questions only to an attested harness.
3. **Guard against poisoning.** A setup is admitted only if reproduction agrees with the contributor's run, and only if adding it doesn't let a known fake pass. Thresholds weight each distinct setup once, so twenty copies of one setup count once.
4. **Recalibrate in public.** Each admission is a signed ledger record with its reasons. The new calibration publishes every member's statistics (numbers only), so anyone can recompute every threshold. Audits logged after it use it, and earlier audits keep the one they cited.

A flagged provider follows the same path. It submits its exact serving setup, and if that reproduces as honest, the threshold moves for everyone. Rewards for contributors come later, once admission has a track record. Details, threats and the document formats to add: [`docs/open-honest-set.md`](docs/open-honest-set.md).

## What the ledger publishes

A reference is a set of signed documents, each naming the ones it builds on by SHA-256. Protocol v2 adds the documents a verdict is judged by.

```mermaid
flowchart BT
  MAN["weights-manifest<br/>every file: path, size, sha256"]
  SET["reference-setup<br/>engine, kernels, GPU, seed"]
  BAT["battery<br/>sealed prompt pool, statistic code digest"]
  RUN["reference-run<br/>sealed answers root"]
  HON["honest-set<br/>honest variants of the same weights"]
  CAL["calibration<br/>thresholds, honest false-positive rate, power"]
  AUD["audit<br/>one provider, one window: draws, verdict"]
  PRO["profile<br/>one model's reference"]
  SET --> MAN
  RUN --> SET
  RUN --> BAT
  HON --> RUN
  CAL --> RUN
  CAL --> HON
  CAL --> BAT
  AUD --> CAL
  AUD --> BAT
  PRO --> MAN
  PRO --> RUN
  PRO --> CAL
```

The signed claims go in an append-only, hash-chained ledger (`registry.jsonl`). The documents sit beside it as `objects/<sha256>.json`, so `sha256sum` on any of them prints its own file name. The ledger head is submitted to the OpenTimestamps calendars and ends up in a Bitcoin block. Every proof is kept in `anchors/`.

| The provider asks | What answers it | How anyone checks |
|---|---|---|
| Which weights? | the weights manifest | `tvc check-hf` compares it with the SHA-256 Hugging Face publishes for every large file, so 988 MB of weights are checked without downloading them. `tvc verify-dir` re-hashes a local copy. |
| How were they run? | the setup record | It can't be changed after publication, and it's specific enough to re-run. It's the publisher's own description, and it says so. |
| Which prompts, which answers? | the run record's two roots | When a verdict is disputed, `tvc reveal` opens the prompts in question with a Merkle proof. `tvc verify-reveal` confirms they were in the set at publication, at that position. |
| Changed afterwards? | ledger order and the Bitcoin timestamp | A record can only cite records already in the ledger, and the anchored head dates the whole ledger up to that point. |
| Were the thresholds fair, and set before you tested me? | the calibration | It's built from honest variants of the same weights and publishes their false-positive rate. `tvc verify-audit` checks it was anchored before the audit was recorded. |
| Did you pick prompts to make me look bad? | the audit's draws | The indices re-derive from the sealed pool, the endpoint and the date. `tvc verify-audit` recomputes them, and the verdict. |

The prompts stay secret on purpose. If they were public, a provider could recognise them and send only those to the real model. So SPOT commits to them first and reveals them one at a time, when there's a reason to. I think this is the one place where publishing everything would make the system easier to cheat.

## Try it

Five commands, from the repository root. None needs a GPU, and only the last two touch the network.

```bash
cargo test --workspace

# The whole story offline, ending with five cheating attempts that get refused.
cargo run --release --bin tvc -- demo

# Check the real reference in reference/ as an outsider would.
cargo run --release --bin tvc -- verify-reference --registry reference/registry.jsonl \
  --profile ef0b8e428ac37ed8b83fdbab395be33ee5cbafc8d8ac38251d220bf643f17f56 \
  --publisher 8f738e4f8e4b3ce2b820dcc9cea88635f0992a56f23eccbc4b5a8d968db421cd

# Compare the published Qwen manifest with Hugging Face, without downloading the weights.
cargo run --release --bin tvc -- check-hf \
  --manifest reference/objects/3f976cbf5f3e4ad9b15f23c1a16987851be036b2179d1025e983f4c68b2cf82c.json

# Ask the calendar whether the ledger head has reached a Bitcoin block yet.
cargo run --release --bin tvc -- verify-anchor --registry reference/registry.jsonl
```

`verify-reference` prints its checks by name and exits non-zero on the first class of failure: 2 ledger, 3 signature, 4 document, 5 weights on disk, 6 anchor. Add `--json` for machine output. [`docs/verify-yourself.md`](docs/verify-yourself.md) walks through every claim with commands you can paste.

## Calibrations and audits a customer can check (protocol v2)

![What the tests caught](docs/img/results.png)

A reference on its own doesn't settle a verdict about a provider. Three more things need to be checkable: that the thresholds came from honest serving variants, that they were fixed before the provider was tested, and that the provider's prompts weren't picked by hand. Protocol v2 adds a document for each step (the formats are in [`docs/spec.md`](docs/spec.md)):

| Document | What it records |
|---|---|
| `battery/v1` | One test: its sealed prompt pool, how many prompts an audit draws, decoding, and the statistic's code by file digest |
| `honest-set/v1` | The honest serving variants of the same weights, and what each one changes |
| `calibration/v1` | The threshold per battery and samples per prompt, the honest false-positive rate, the measured power against named substitutes and partial routing, and what it can't detect |
| `audit/v1` | One endpoint in one time window: the calibrations it's judged by, the drawn prompt indices, a sealed root of the responses, each statistic, the T0 result and the verdict |

The Qwen2.5-7B reference is now published this way as profile `ef0b8e42`: 4 batteries, 4 honest sets of 5 variants, 4 calibrations with power against 6 alternatives, 78 documents in all. Prompts and outputs stay sealed; 283 sample strings were checked against the published objects and none appear.

```bash
cargo run --release --bin tvc -- verify-reference --registry reference/registry.jsonl \
  --profile ef0b8e428ac37ed8b83fdbab395be33ee5cbafc8d8ac38251d220bf643f17f56 \
  --publisher 8f738e4f8e4b3ce2b820dcc9cea88635f0992a56f23eccbc4b5a8d968db421cd
```

`tvc verify-audit` checks an audit in twelve steps. The ones that matter to a customer:
- **The thresholds came first.** Every calibration the audit cites is earlier in the ledger, and an anchor proof made before the audit was recorded covers it. `tvc anchor` now keeps every proof in `reference/anchors/`, so that evidence isn't overwritten.
- **The prompts weren't picked.** Each battery's indices re-derive from its sealed pool and a context built from the endpoint, the day and the battery (`tvc audit-draw` prints them).
- **The verdict follows from the numbers.** Every threshold is the calibration's, and every verdict is recomputed. When the prompt-token check (T0) fails, the verdict must be `misconfigured`, never a swapped model.
- **Any one answer can be opened.** `tvc reveal` on the audit's sealed responses, checked with `--reveal`.

Two demo audits are in the ledger. No provider was queried: each "endpoint" is a stored GPU run standing in for one, and the audit says so. Provider A is the 4-bit AWQ copy. On the two tests drawn, its statistics are 0.1983 against a threshold of 0.1239 and 0.0259 against 0.0009, so the verdict is `inconsistent-with-declared-configuration`. Provider B is the real weights with CUDA graphs off. It's inside both bands, so the verdict is `consistent`.

```bash
cargo run --release --bin tvc -- verify-audit --registry reference/registry.jsonl \
  --audit 241d9fca72893b44f6635e5088c4d69ed53f0ebb6e4d93b4decbd1805cafb00a \
  --publisher 8f738e4f8e4b3ce2b820dcc9cea88635f0992a56f23eccbc4b5a8d968db421cd
```

The scripts that built these are in authenticated.si's private repository with the prompt sets. Still to build: retiring prompts once revealed, batching thousands of audits a day into one ledger record, contributor and analyst keys, and a fully public battery anyone can rerun.

## A GPU reference, and what the tests catch: Qwen2.5-7B-Instruct

The second reference was run on an NVIDIA L4 with vLLM 0.30.0, as an [OpenResearch](https://github.com/alphaXiv/OpenResearch) experiment tree: one git branch per question, one fixed run command, every number printed to the run log. The harness, the prompt sets and the write-ups are authenticated.si's and live in a private repository. Each test follows a published method, so its results can be compared with the paper: prompt-token counts (AgentProv, arXiv 2609.00052), answer distributions (One Token Is Enough, arXiv 2607.10252), rank uniformity (RUT, arXiv 2506.06975), kernel two-sample tests (MET, arXiv 2410.20247) and random-generation probes (IRIS, arXiv 2607.20860).

**Round 1: which engine makes the reference.** With vLLM's default kernels, 12 of 32 greedy answers changed depending on what else was in the batch. With its batch-invariant kernels, 32 of 32 stayed the same, at 5-8% lower throughput. So the reference is run batch-invariant: anyone with the same stack gets the same reference. A provider won't run that stack, so the reference is still compared as a distribution of answers, not as exact strings.

**Round 2: honest providers against substitutes.** Ten sample sets were collected against the reference. Five are honest variants of the same weights (default kernels, 8 sequences per batch, prefix cache off, CUDA graphs off, fp16). Five are cheaper things a provider could serve instead.

- With a plain p-value, the MET test flags all five honest variants (p = 0.001). Kernel choice alone moves the output distribution enough to be seen. This matches what the literature reports for real providers.
- With the threshold taken from the honest variants (95th percentile of the statistic, each honest variant judged only against the others), honest variants are flagged 6-10% of the time on average.
- At that threshold, a 4-bit AWQ copy, Qwen2.5-3B and Qwen2-7B are flagged by every test at every budget down to 5 samples per prompt. Online fp8 (weights and activations) is flagged 95% of the time at 10 samples per prompt.
- An 8-bit weight-only copy (GPTQ int8) is not flagged by anything. It sits at the honest rate.
- The prompt-token check alone catches an injected provider system prompt and the Qwen2 template, because both change the token count. Without that gate, the system prompt makes the text tests fire as if the model had been swapped.
- Routing 10% of answers to a different model is caught. Routing to a 4-bit copy needs about 20% before it's caught reliably.

This reference is published in the ledger as profile `a8ce6958`: the weights manifest (all 11 files match Hugging Face at `a09a354`), the setup, and one run per battery with its band.

```bash
cargo run --release --bin tvc -- verify-reference --registry reference/registry.jsonl \
  --profile a8ce6958e740643c007bae59e0a141750c07146f1ffae20a68c30e8f45c66b2e \
  --publisher 8f738e4f8e4b3ce2b820dcc9cea88635f0992a56f23eccbc4b5a8d968db421cd
```

Known limits of this round: one model, one GPU type, one engine, and only five honest variants, so the threshold itself is noisy (the worst honest variant was flagged up to 45% of the time on one test). The literature review behind these choices (the 24 papers we were given plus later work) is [`docs/reference-tests-literature.md`](docs/reference-tests-literature.md).

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
- **The outputs came from the model.** They're what the publisher says the model said. On a pinned stack the 0.5B run reproduced 12 of 12, and the 7B run with batch-invariant kernels 32 of 32. Across GPUs and engines, outputs drift, so third-party re-runs and provider endpoints are compared within bands taken from honest serving variants, not byte for byte.
- **The Bitcoin block is real.** `verify-anchor` reads the proof and prints the block height and the merkle root it claims. It doesn't fetch blocks. You finish the check on any block explorer.
- **The key is SPOT's.** A key is 32 bytes. Pin it from somewhere you already trust.

## Why Bitcoin

The only thing the timestamp is for is the fourth question: did SPOT change its reference after seeing a provider's output. Signatures and hashes can't answer that, because SPOT holds the key and could sign a new reference with any date it likes. It takes a party SPOT doesn't control to say "this existed by then". OpenTimestamps puts the commitment in a Bitcoin block for free, with no account. Sigstore's Rekor log would also work, and the `Anchor` trait in `tvc-cli/src/anchor.rs` is where it would go.

The upgrade from "pending" to "in a block" takes a few hours. `tvc verify-anchor` asks the calendar for it and stores it when it's ready. The tool only contacts calendars on the reference client's default list, over HTTPS, because the URL comes out of a file.

## How it fits with secure-hardware inference

Confidential-inference providers run models inside Intel TDX or AMD SEV enclaves and publish attestations. [awesome-private-inference](https://github.com/amiller/awesome-private-inference) re-checks them daily, and its findings show the weak point is "which model". For Chutes, "`model_name`/`revision` are never bound to the quote". For RedPill/Phala, model-weight provenance is listed as unknown.

ModelCert isn't an enclave and doesn't replace one. It gives "which weights" a signed, provider-independent name an attestation could cite, and it applies the same discipline to the checker. Confidential GPUs are also how Phase 3 of the open honest set keeps the secret questions secret on a contributor's machine.

## What's next

Roughly in order:

1. **Certificates, receipts and settlement:**
    - provider certificates and revocations as ledger documents;
    - a receipt format signed by the gateway, published in hourly batches as one Merkle root;
    - x402 payments held until the certificate covering the answer has held for its settlement window;
    - `tvc verify-receipt`, so anyone can check a receipt and its chain offline.
2. **Open honest set, Phase 1:**
    - contributor keys;
    - a public battery per model;
    - contribution, replay and admission records;
    - calibrations that publish every member's statistics, and `tvc calibrate`.
3. A witnessed transparency log in place of the hash chain, so many signers share one history ([`docs/transparency-log-plan.md`](docs/transparency-log-plan.md)).
4. References for the open models OpenRouter resells most, then certificates for the providers that serve them.
5. **Open honest set, Phases 2 and 3:** single-use question slices, then confidential-GPU contributions, then rewards for contributors.

## Commands

| Command | What it does |
|---|---|
| `manifest` | Hash every file in a model directory into a weights manifest. |
| `verify-dir` | Check that a directory holds exactly the files a manifest lists. |
| `check-hf` | Compare a manifest with Hugging Face at its pinned commit. |
| `commit-items` | Commit to a JSONL file of secret items (prompts or outputs) with fresh salts. |
| `reveal`, `verify-reveal` | Open one committed item with its proof, and check it. |
| `publish`, `show` | Sign a document into the ledger, and print one back. |
| `verify-reference` | Check a profile and everything it cites, check by check. |
| `audit-draw` | Print the question indices an audit must use from a battery. |
| `verify-audit` | Check an audit: calibration first, questions not picked, verdict follows from the numbers. |
| `anchor`, `verify-anchor` | Timestamp the ledger head (every proof is kept in `anchors/`), and follow the proofs to a Bitcoin block. |
| `audit` | Re-derive every digest in the ledger and list its records. |
| `keygen` | Generate a signing key. |
| `demo` | All of the above, offline, with the cheating attempts at the end. |

The record formats, the canonical JSON rules, the item leaf and the signing domains are in [`docs/spec.md`](docs/spec.md).

## Repository layout

```
tvc-core/src/
  canonical.rs     canonical JSON and content digests
  manifest.rs      per-file weight manifests
  itemset.rs       salted item commitments, reveals, Fiat-Shamir selection
  merkle.rs        the Merkle tree under item sets
  documents.rs     the document kinds and the object store
  audit.rs         how an audit draws its questions and reaches its verdict
  registry.rs      the append-only ledger of signed document claims
  signer.rs        BIP-340 keys and document claims
  digest.rs, hex.rs, error.rs
tvc-cli/src/
  main.rs          the tvc binary
  reference.rs     manifest, publish, reveal and verify-reference commands
  audit.rs         audit-draw and verify-audit
  hf.rs            the Hugging Face comparison
  anchor.rs        OpenTimestamps submission, parsing and upgrade
reference/         the real ledger (Qwen2.5-0.5B and Qwen2.5-7B references, demo audits), anchors/
reference/gpu/     (ignored) where authenticated.si's private harness is cloned
docs/              how it works, spec, open honest set design, verify-yourself walkthrough, research digest
```

An earlier version of this repository also committed to quantised model weights and registered them under a publisher key. That flow answered a different question, it was never used by a published reference, and it's been removed. It remains in the git history.

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
