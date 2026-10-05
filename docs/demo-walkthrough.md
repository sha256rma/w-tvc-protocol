# Demo walkthrough (about 10 minutes)

Every step below was run from a fresh clone on 5 October 2026. You need Rust 1.85 or newer. No GPU, no account, no API key. Steps 5 and 8 use the network (Hugging Face and the OpenTimestamps calendars); everything else is offline.

## What you are checking

authenticated.si tests whether an AI provider serves the open model it claims. It runs the real model on its own GPU to build a reference, then compares providers against it, using test questions it keeps secret. W-TVC lets anyone check that this process was fair without seeing the questions:
- which exact model files the reference used;
- that the thresholds were fixed before a provider was tested;
- that the questions weren't picked by hand;
- that every verdict follows from the published numbers;
- that none of it changed afterwards (Bitcoin timestamps).

The publisher key below is a demo key, not authenticated.si's production key.

```bash
P=8f738e4f8e4b3ce2b820dcc9cea88635f0992a56f23eccbc4b5a8d968db421cd
```

## 1. Build and test (2 minutes)

```bash
git clone https://github.com/sha256rma/w-tvc-protocol.git && cd w-tvc-protocol
cargo build --release
cargo test --release --workspace
```

Expect 189 passing tests (31 + 149 + 8 + 1).

## 2. The whole story offline, with cheating attempts

```bash
./target/release/tvc demo
```

It publishes a reference, checks it, then tries five ways to cheat (editing a document, a wrong signer, swapped weights and others). Each one is refused, with the reason.

## 3. Check a real reference made on a GPU

Qwen2.5-7B-Instruct, run with vLLM on an NVIDIA L4. Profile v2 includes its four tests, the honest serving variants used to set thresholds, and the calibrations.

```bash
./target/release/tvc verify-reference --registry reference/registry.jsonl \
  --profile ef0b8e428ac37ed8b83fdbab395be33ee5cbafc8d8ac38251d220bf643f17f56 --publisher $P
```

Nine checks, all PASS:
- the ledger chain is intact;
- every document (78 of them) is signed by the key;
- every file hashes to its name;
- the honest variants used the same weights;
- the Bitcoin proof covers the profile.

## 4. Check a verdict about a provider

Two demo audits are in the ledger. No real provider was queried: each "provider" is a stored GPU run, and the audit says so.
- Provider A is a 4-bit compressed copy of the model.
- Provider B is the real weights served differently.

```bash
./target/release/tvc verify-audit --registry reference/registry.jsonl \
  --audit 241d9fca72893b44f6635e5088c4d69ed53f0ebb6e4d93b4decbd1805cafb00a --publisher $P
./target/release/tvc verify-audit --registry reference/registry.jsonl \
  --audit 35e2d75ae06ba6f47944e2d5fbaf297da2a2b08a8bfa0848ff709cdca07749f1 --publisher $P
```

Provider A comes out `inconsistent-with-declared-configuration`; Provider B comes out `consistent`. Both pass all checks. The four that matter:
- `calibration_before_audit` and `calibration_anchored_first`: the thresholds were in the ledger, and in a Bitcoin-anchored proof, before the audit was recorded;
- `draws_rederive`: the questions the audit used are re-derived from the sealed question set, the endpoint and the date, so nobody picked them;
- `thresholds_match` and `verdict_follows`: every threshold is the calibration's, and every verdict is recomputed from the numbers.

## 5. The model files are the real ones (network)

```bash
./target/release/tvc check-hf \
  --manifest reference/objects/718ab94dc423cd1b5ee1d359f95a03eacd71a5dbc763705b110938f27d72e9ec.json
```

Each of the 11 files the reference loaded matches the SHA-256 Hugging Face publishes for Qwen2.5-7B-Instruct at commit a09a354, checked without downloading 15 GB of weights.

## 6. Try to cheat

Raise a published threshold so the 4-bit copy would pass, and run the check again:

```bash
F=reference/objects/a72fe242000388326731791e4c74387794e801505d1c797914fe09530fbd8f3d.json
cp $F /tmp/backup.json
sed -i.bak 's/"0.000895"/"0.009"/' $F
./target/release/tvc verify-audit --registry reference/registry.jsonl \
  --audit 241d9fca72893b44f6635e5088c4d69ed53f0ebb6e4d93b4decbd1805cafb00a --publisher $P
cp /tmp/backup.json $F && rm -f $F.bak
```

`objects_match_digests` fails ("the file was edited"), and so does `thresholds_match`. A changed document can't keep its name, and the signed ledger names every document.

## 7. Open one secret question with a proof

The test questions are sealed. When a verdict is disputed, single questions can be opened. Here is one from the small Qwen2.5-0.5B reference:

```bash
./target/release/tvc verify-reveal --registry reference/registry.jsonl \
  --reveal reference/reveals/prompt-6.json \
  --run 8ca35b9b7b16f5968a713efbed9f2c00dc080ee46cb65085318df909756123d5 --set prompts
```

It proves "What is the capital of Australia? Answer with one word." was in the sealed set from the start. Open the model's answer the same way:

```bash
./target/release/tvc verify-reveal --registry reference/registry.jsonl \
  --reveal reference/reveals/output-18.json \
  --run 8ca35b9b7b16f5968a713efbed9f2c00dc080ee46cb65085318df909756123d5 --set outputs
```

The answer is "Sydney.": the reference records what the real model says, not the right answer. A provider that answers "Canberra" is serving something else.

## 8. It all existed by a known time (network)

```bash
./target/release/tvc verify-anchor --registry reference/registry.jsonl
```

All three stored proofs are in Bitcoin: blocks 969564, 969627 and 969658. The latest covers every record. To finish the check, look up block 969658 on any block explorer and compare its merkle root with the one printed.

## Where to read more

- How it fits together, with diagrams: [`docs/how-it-works.md`](how-it-works.md)
- Document formats and checks: [`docs/spec.md`](spec.md)
- What the GPU experiments found: the README sections "A GPU reference" and "Calibrations and audits"
- What's next for the protocol: [`docs/transparency-log-plan.md`](transparency-log-plan.md)
