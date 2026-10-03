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
