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
