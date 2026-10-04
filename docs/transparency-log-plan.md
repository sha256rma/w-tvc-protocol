# From a Bitcoin-anchored hash chain to a witnessed transparency log

Status: proposal, 3 October 2026. Nothing here is built yet.

## Why change anything

W-TVC exists so that a provider flagged by authenticated.si, or a customer reading a verdict, can check three things without trusting authenticated.si:

1. **Timing.** The reference, the honest set, the thresholds and the sealed questions existed before the audit.
2. **One history.** There is one version of each. authenticated.si didn't keep several calibrations and pick the one that suited a verdict afterwards.
3. **Cheap verification.** A customer can check a single verdict quickly, without downloading everything.

Today W-TVC keeps a signed, hash-chained ledger (`registry.jsonl`) and timestamps its head with OpenTimestamps in Bitcoin. That covers point 1, but not points 2 and 3:

- **Bitcoin proves a hash existed by a block, not that it was the only one.** OpenTimestamps will timestamp any hash it's given. A publisher could keep ten ledgers with ten different calibrations, timestamp all of them, audit a provider, then show the ledger that fits. Every proof would be valid. Bitcoin doesn't stop split views.
- **Verification is slow and partial.** Proofs land in a block after hours. `tvc verify-anchor` prints the block height and merkle root the proof claims, and asks the user to check them on a block explorer; it doesn't verify block headers itself.
- **A hash chain doesn't scale to audits.** To check one record, a verifier replays the whole chain. With daily audits of many providers for many models, that's thousands of records a day.

The standard answer to "an authority that could rewrite history" is a **transparency log**, as used by Certificate Transparency for web certificates, Sigstore's Rekor for software signatures, and Go's checksum database for modules: an append-only Merkle tree, signed checkpoints, and independent witnesses.

## The five changes

### 1. Keep the documents and the checks

The document kinds (`weights-manifest`, `reference-setup`, `battery`, `reference-run`, `honest-set`, `calibration`, `audit`, `profile`), canonical JSON, content digests, signatures and the checks in `verify-reference` and `verify-audit` stay as they are. They don't depend on how the log is built. Only what proves "this document is in the one history, and was there before that one" changes.

### 2. Replace the hash chain with an append-only Merkle tree log

Each record (a signed document claim, as today) becomes a leaf of a Merkle tree, in append order, using RFC 6962 hashing (the one Certificate Transparency uses: leaf hash `SHA-256(0x00 || leaf)`, node hash `SHA-256(0x01 || left || right)`).

That gives two proofs, each logarithmic in the log size:
- **Inclusion proof:** this record is leaf `i` of the tree of size `n` with root `r`. A customer checks one audit with about 20 hashes, not the whole log.
- **Consistency proof:** the tree of size `n2` extends the tree of size `n1`, and nothing was removed or changed. Anyone holding an old root can check the log only grew.

The log is published as static files in the tiled layout of the C2SP `tlog-tiles` specification (the format Go's checksum database and Sigstore's newer logs use), so it can be served from any static host or CDN, and mirrored by anyone.

Migration: the existing 92 records become the first 92 leaves, in the same order. The old hash chain stays readable for the old proofs.

### 3. Signed checkpoints with independent witnesses

**Checkpoints.** After each batch of appends (every few minutes at most), authenticated.si signs a checkpoint in the C2SP `tlog-checkpoint` format: origin name, tree size, root hash, signature. It's a few lines of text.

**Witnesses.** A witness is an independent party that keeps the last checkpoint it saw, and cosigns a new one only after verifying a consistency proof from the old one. If authenticated.si showed two different histories, no honest witness would cosign both. That prevents the split-view attack Bitcoin timestamps can't.

- Use existing public witness networks (the transparency-dev / Sigsum witnesses accept new logs) rather than running our own.
- Policy: a checkpoint counts when at least 2 of 3 named witnesses have cosigned it. `verify-audit` enforces that and rejects a checkpoint without enough cosignatures.
- Witness cosignatures also give time: a witness records when it saw a checkpoint, so a calibration's inclusion in a witnessed checkpoint dated before the audit window answers point 1 within minutes, not hours.

Fallback if witness onboarding is slow: submit each checkpoint to Sigstore's public Rekor log (free, run by the OpenSSF, itself a monitored transparency log). It's weaker than independent witnesses, because it's one operator, but still public and append-only.

### 4. A receipt with every verdict

The authenticated.si API returns, with each verdict:
- the audit document's digest;
- the checkpoint (tree size, root, signature, witness cosignatures);
- the inclusion proof for the audit and for each calibration it cites.

`tvc verify-audit --receipt receipt.json` checks all of it offline in milliseconds:
- the audit and calibrations are in the witnessed tree;
- the calibrations' leaves come before the audit's;
- the calibrations were in a checkpoint witnessed before the audit window started;
- the existing threshold, draw and verdict checks.

Receipts also make customers into monitors. Any two receipts can be checked against each other with a consistency proof, and a split view would show up.

### 5. Keep Bitcoin, as a daily extra

Timestamp one checkpoint per day with OpenTimestamps. It's free and costs one scheduled job. Calibrations are published days before they're used, so the delay doesn't matter. Its job is a neutral long-term time record that doesn't depend on any witness still existing in ten years. It stops being the foundation of the protocol.

## What this doesn't solve, and what does

A log proves the publisher didn't change what it published. It doesn't prove the reference was right, or that the publisher ran what it says it ran. Three things address that, and they matter more to trust than the log does:

- **Reproducibility.** Publish a small public calibration set: questions plus our reference answers, so anyone with a GPU can rerun the setup and compare their samples with ours inside the published honest band.
- **Reveal on dispute.** Opening sealed questions with Merkle proofs when a verdict is disputed is already supported (`tvc reveal`, `--reveal`). Revealed questions are retired from future audits.
- **Other auditors.** The formats are open. Another lab can publish its own references and calibrations under its own key, in its own log, and a provider's results can be compared across auditors.

## Order of work

1. Merkle-tree log library in `tvc-core`: leaf and node hashing, inclusion and consistency proofs, with RFC 6962 test vectors. No new dependencies beyond what's already allowed (`bitcoin_hashes` for SHA-256).
2. Tiled static layout and checkpoint signing in `tvc-cli` (`tvc log append`, `tvc log checkpoint`), plus migration of the existing ledger.
3. `verify-audit --receipt` and `verify-reference --receipt` with inclusion and consistency checks.
4. Witness integration: cosignature format (C2SP `tlog-cosignature`), the 2-of-3 policy, submitting checkpoints to the public witness network. Rekor fallback.
5. Receipts in the authenticated.si API, and a short page explaining how a customer checks one.
6. Daily OpenTimestamps anchor of one checkpoint, and retire the per-append anchoring.

Each step is useful on its own: steps 1-3 already fix scaling and give cheap verification; step 4 fixes split views.

## References

- RFC 6962 / RFC 9162, Certificate Transparency (Merkle tree hashing, inclusion and consistency proofs).
- C2SP specifications: `tlog-checkpoint`, `tlog-cosignature`, `tlog-tiles` (github.com/C2SP/C2SP).
- Sigstore Rekor (transparency log for software signatures).
- Go checksum database, sum.golang.org (a tiled log with witnesses in production).
- Sigsum (minimal transparency log with witness cosigning).
- OpenTimestamps (Bitcoin timestamping, kept as the daily extra).

## Addendum, 4 October 2026: keeping Bitcoin as the anchor

The owner prefers Bitcoin as the anchor, for the same reason people choose open models: nobody controls it. Bitcoin can also close the split-view gap, without relying on witnesses, by chaining the anchors.

**Chained anchors (single-use seals).**
- Each checkpoint is committed in a Bitcoin transaction (an `OP_RETURN` with the checkpoint's root hash and tree size) that spends one output of the previous anchor transaction.
- The first anchor's output is published in the W-TVC repository and on authenticated.si.
- An output can be spent only once, so the anchors form one line. Publishing two different histories would mean spending the same output twice, which Bitcoin rejects.
- A verifier walks the chain from the published first output. Each transaction must spend the previous anchor's output, and each committed checkpoint must extend the one before (consistency proof).
- This is the single-use seal idea (Peter Todd), and the approach Mainstay used to give logs a single history on Bitcoin.

**Cost.** One small transaction per anchor, a few hundred to a few thousand satoshis at typical fee rates. A daily anchor is enough, since calibrations are published days before they are used. Audits within the day are covered by the next anchor and by the receipts.

**What changes in the plan.** Chained Bitcoin anchors take over the timing and the single-history job from the witnesses (change 3), and from OpenTimestamps (change 5). Witnesses and receipts still help: they give the time within the day, before the next anchor confirms. OpenTimestamps can stay as a free extra.

## Addendum: why references come from weights we run

W-TVC is built for references that the publisher computes from weights it holds. A reference taken from a provider's API, including the lab's own, gets much weaker guarantees. That's why authenticated.si builds every reference on its own GPUs.

| What a verifier can check | Reference from weights we ran | Reference from a provider's API |
|---|---|---|
| Which exact files were used (`weights-manifest`, `tvc check-hf`) | Yes: every file's SHA-256 matches Hugging Face at a pinned commit | No: nobody outside the provider can hash its weights |
| How it was run (`reference-setup`) | Engine, version, kernels, GPU, seed, request settings; specific enough to rerun | Only the API name and parameters; the serving stack is hidden |
| Can someone else reproduce it? | Yes: same weights and setup give the same answer distribution (on the same stack, the same greedy answers) | No: the API can change silently. Log Probability Tracking found 37 silent changes on 189 OpenRouter endpoints in four months |
| Is the honest band measured? (`honest-set`, `calibration`) | Yes: we serve the same weights several honest ways and measure the spread | Only by sampling the API over time, with no control over what changed |
| Does a disputed answer hold up? (`tvc reveal`) | A third party reruns the revealed question on the same weights and checks the answer is plausible | Nobody can rerun the API as it was on that day |
| Was it fixed before the audit? (log and anchor) | Yes | Yes |

**What W-TVC still doesn't prove,** even with local weights: that the published answers came from those weights rather than being made up. Three things limit that:
1. Reproducibility: a public calibration set anyone can rerun on the same weights.
2. Reveals: any revealed question can be rerun on the same weights by a third party.
3. Later, running references inside a confidential GPU (H100 and Blackwell support confidential computing), so a hardware attestation binds the weights' hash to the outputs. Only a publisher that runs the weights itself can do this.
