# W-TVC record and document formats

This is enough to check a W-TVC ledger without this code. Every rule here is
implemented once, in the file named beside it, and covered by tests there.

## Canonical JSON (`tvc-core/src/canonical.rs`)

A document's identity is the SHA-256 of its canonical bytes:

- object keys sorted by their UTF-8 bytes, no whitespace anywhere;
- strings escaped the way `serde_json` writes them (`"` and `\` escaped, control characters as `\n`, `\t` or `\uXXXX`, everything else as raw UTF-8);
- numbers must be integers. Decimals are written as strings, for example `"0.7"`;
- arrays keep their order.

The digest is plain SHA-256, untagged. `printf '{}' | shasum -a 256` gives `44136fa3...`, and so does `tvc`.

A stored object is accepted only if re-encoding it gives back the same bytes, so one document can't have two spellings.

## Document kinds (`tvc-core/src/documents.rs`, `manifest.rs`)

Every document has a `kind` field of the form `<name>/v<number>`. Digests are 64 lowercase hex characters.

| Kind | Required fields | Cites (in this order) |
|---|---|---|
| `weights-manifest/v1` | `model`; `files`: `[{path, size, sha256}]`, sorted by path bytes, no duplicates, no `.` or `..` components. Optional `hf_repo` and `hf_commit` (a 40-character commit, never a branch), given together. | nothing |
| `reference-setup/v1` | `weights`, `engine`, `engine_version`, `dtype`, `hardware`, `context_length` (integer), `decoding` (object of decimal strings). Optional `chat_template_sha256`. Other fields are allowed. | `weights` (a manifest) |
| `reference-run/v1` | `setup`, `date` (YYYY-MM-DD), `prompts` and `outputs` (each `{root, count}`), `samples_per_prompt`, `bands`: `[{check, metric, reference, low, high, samples}]`, with the values as decimal strings. Optional `determinism`: `{repeats, exact_matches}`. `outputs.count` must equal `prompts.count × samples_per_prompt`. | `setup` (a setup) |
| `profile/v1` | `model`, `version`, `maturity` (`skeleton`, `working` or `full`), `weights`, `runs` (array). A working or full profile needs at least one run. | `weights` (a manifest), then each of `runs` (runs) |

### Protocol v2: calibrations and audits

Additive. Every v1 kind still validates, and a v1 profile still verifies.

| Kind | Required fields | Cites (in this order, each digest once) |
|---|---|---|
| `battery/v1` | `id`, `version`, `pool` `{root, count}` (a committed prompt set), `draw` `{k, ...}` with `k <= pool.count`, `decoding` (decimal strings), `normalisation`, `statistic` `{name, code: {repo, commit, path, sha256}}`, `signals` (strings). | nothing |
| `reference-setup/v2` | The v1 setup fields, plus `kernel_mode`, `gpu`, `driver`, `seed` (integer), `harness` `{repo, commit}`, `lock_sha256`, `request` (object). | `weights` (a manifest) |
| `reference-run/v2` | The v1 run fields, plus `battery` and `evidence_sha256` (the raw run log). Its `prompts.root` is the battery's pool root unless `prompts_subset_of_pool` is true (checked by `verify-reference`). | `setup` (either setup version), `battery` |
| `honest-set/v1` | `reference_run`, `members`: `[{setup, run, differs}]`, at least one. | `reference_run`, then each member's `setup` and `run` |
| `calibration/v1` | `reference_run`, `honest_set`, `quantile`, `method`, `entries`: `[{battery, k, threshold, honest_fpr_mean, honest_fpr_max, power: [{against, label, eps, rejection_rate}]}]` with at most one entry per (battery, k), `cannot_detect` (strings). | `reference_run`, `honest_set`, each entry's `battery`, each `power[].against` (runs) |
| `audit/v1` | `endpoint` `{host, model, ...}`, `window` `{start, end}` as `YYYY-MM-DDTHH:MM:SSZ`, `calibrations` (at least one), `draws`: `[{battery, k, indices}]` with exactly `k` indices, `responses` `{root, count}`, `results`: `[{battery, k, statistic, threshold, verdict}]`, `t0` `{matches: bool}`, `verdict`, `confidence`. Optional `better_match` `{calibrations, results}`, required when the verdict is `different-model`. | each of `calibrations`, each draw's `battery`, each of `better_match.calibrations` |
| `profile/v2` | The v1 profile fields, plus `calibrations` (at least one when `full`). Runs may be v1 or v2. | `weights`, each of `runs`, each of `calibrations` |

A battery verdict is `inside-band` when `statistic <= threshold`, compared exactly as decimals (`decimal_cmp`, no floating point). Otherwise it's `outside-band`, or `inconclusive-T0` when `t0.matches` is false. The overall verdict (`tvc_core::audit::overall_verdict`):
- `t0.matches` false gives `misconfigured`;
- every battery inside gives `consistent`;
- otherwise, a `better_match` whose results are all inside its own calibrations gives `different-model`;
- otherwise `inconsistent-with-declared-configuration`.

An audit's indices for a battery are `select(pool.root, context, pool.count, battery.draw.k)`, where `context` is the canonical JSON of `{"battery": <battery digest>, "date": <first 10 characters of window.start>, "endpoint": <the audit's endpoint object>}` (`tvc_core::audit::draw_context`). `tvc audit-draw` prints them.

Any other kind is stored without field checks. If it cites anything, it lists the digests under a top-level `refs` array.

## Item sets (`tvc-core/src/itemset.rs`)

Prompts and outputs are committed as two separate sets. Each set is a JSONL file, one item per line, in order. For item `i` with a fresh 32-byte random salt `s_i`:

```
leaf_i = tagged_hash("W-TVC/v2/item-leaf", [u64_be(i), s_i, canonical(item_i)])
```

`tagged_hash(tag, parts)` is the BIP-340 construction `SHA256(SHA256(tag) || SHA256(tag) || m)`, where `m` is each part prefixed with its length as a big-endian `u64`.

The root is the Merkle tree over the leaves:
- internal node = `tagged_hash("W-TVC/v1/weight-node", [left, right])`;
- an odd node at the end of a level is promoted unchanged, never duplicated;
- an opening lists only sibling hashes;
- direction comes from the index, and the number of steps from the item count;
- so there's exactly one accepting path for each item.

A reveal is `{kind: "item-reveal/v1", index, count, salt, item, siblings}`.

Selection (`tvc sample`): to pick `k` of `n` items, hash `tagged_hash("W-TVC/v2/item-select", [root, context, u64_be(counter)])` for counter 0, 1, 2 and so on. Read each digest as four big-endian `u64` draws. With `M = 2^64 - 1`, reject any draw at or above `M - (M mod n)`, take the rest `mod n`, and keep the distinct ones until there are `k`. Return them sorted.

## Ledger lines (`tvc-core/src/registry.rs`)

One JSON object per line. Every line has `v`, `sequence` (starting at 0, shared by all kinds), `previous` (the digest of the line before, all zeros for the first) and `digest`.

`v: 2` is a model registration, documented in `docs/weight-commitment.md`.

`v: 3` is a document claim:

```
{v, sequence, kind, document, refs: [hex], timestamp, signer, signature, previous, digest}

sighash = tagged_hash("W-TVC/v2/document/" + kind,
                      [signer, kind, document, u64_be(len(refs)), refs..., u64_be(timestamp)])
digest  = tagged_hash("W-TVC/v2/ledger-document",
                      [previous, u32_be(v), u64_be(sequence), kind, document,
                       u64_be(len(refs)), refs..., u64_be(timestamp), signer, signature])
```

`signature` is BIP-340 over `sighash`, and `signer` is the x-only public key.

A reader refuses a line when:
- its version is unknown;
- its digest doesn't recompute;
- its signature doesn't verify;
- its document digest already appeared;
- any of its `refs` isn't the document of an earlier line.

`refs` must also equal what the document itself cites (the table above). That's checked by whoever holds the documents, which is what `tvc verify-reference` does.

## Anchor (`tvc-cli/src/anchor.rs`)

`registry.head.ots`, beside the ledger, is a standard OpenTimestamps file whose digest is a ledger record's `digest`. The anchor covers that record and everything before it.

`tvc anchor` also keeps every proof in `anchors/<covered sequence>-<head prefix>.ots` and never deletes one, because `verify-audit` needs the proof that existed when an audit was recorded, not only the latest. `tvc verify-anchor` checks and upgrades all of them.

## verify-reference checks (`tvc-cli/src/reference.rs`)

In order:
1. `ledger_chain_intact`
2. `profile_in_ledger`
3. `signed_by_publisher`
4. `objects_match_digests`
5. `documents_well_formed`
6. `references_match_claims`
7. `runs_use_profile_weights`
8. `weights_on_disk` (with `--weights-dir`)
9. `anchored_after_profile`

Each reports `pass`, `fail` or `skip`. The exit code is the class of the first failure: 2 ledger, 3 profile or signature, 4 document, 5 weights, 6 anchor. It's 0 if every check that ran passed.

## verify-audit checks (`tvc-cli/src/audit.rs`)

In order:
1. `ledger_chain_intact`
2. `audit_in_ledger`
3. `signed_by_publisher`
4. `objects_match_digests`
5. `documents_well_formed`
6. `references_match_claims`
7. `calibration_before_audit`: every cited calibration is an earlier record than the audit
8. `calibration_anchored_first`: a stored anchor covers the latest calibration and doesn't cover the audit, so the calibration was timestamped before the audit was recorded
9. `draws_rederive`: each draw's `k` is the battery's, its indices re-derive, and every result's battery was drawn
10. `thresholds_match`: each result's threshold is the cited calibrations' for its (battery, k)
11. `verdict_follows`: battery and overall verdicts recompute
12. `reveals_open` (with `--reveal`): each revealed item opens against the responses root or a drawn battery's pool

Exit codes: 2 ledger, 3 audit or signature, 4 document or reveal, 6 anchor, 7 order, 8 draw, 9 thresholds or verdict; 0 if every check that ran passed.

`verify-reference` on a `profile/v2` also checks that the setups of the profile's runs and of every honest set its calibrations cite use the profile's weights (substitute runs named under `power` may not), that each v2 run's prompts are its battery's pool, and that a `full` profile has honest sets of at least 4 and power measured against at least 2 runs.

### What these checks prevent, and what they don't

| Attack | Stopped by |
|---|---|
| Changing a reference after auditing a provider | hash chain and anchor (`anchored_after_profile`) |
| Tuning thresholds after seeing a provider's answers | `calibration_before_audit`, `calibration_anchored_first` |
| Picking prompts that make a provider look bad or good | `draws_rederive` |
| A verdict that contradicts the numbers | `thresholds_match`, `verdict_follows` |
| Calling a provider that changed the prompt a "different model" | the T0 gate in `verdict_follows` |
| Disputing one answer | `reveals_open` |

Not stopped:
- 8-bit weight-only quantisation. It sits inside the honest band, and calibrations say so in `cannot_detect`.
- Routing a small share of traffic to a close relative. Calibrations publish the measured power per `eps` instead.
- A publisher reporting statistics it never measured. Reveals on dispute limit this. A fully public calibration battery that anyone can rerun is planned.
- A provider that recognises audit traffic and serves it the real model.
