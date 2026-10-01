# Demo script (about 4 minutes)

One terminal, large font, the repository root as the working directory. Build first,
so nothing compiles on camera:

```bash
cargo build --release --bin tvc && alias tvc=./target/release/tvc
clear
```

The lines under "Say" are talking points. Say them your own way.

## 0:00 The problem (30 s)

Show `https://authenticated.si`, or the README's "The problem" section.

Say: providers sell open models by name, and some serve a cheaper model or a 4-bit
copy under that name. SPOT catches that by comparing the endpoint with reference
answers from running the real model. But then the provider asks: which weights did
*you* run, on which prompts, and did you change your answers after seeing mine?
W-TVC is how we answer that without asking anyone to trust us.

## 0:30 Which weights (50 s)

```bash
tvc check-hf --manifest reference/objects/3f976cbf5f3e4ad9b15f23c1a16987851be036b2179d1025e983f4c68b2cf82c.json
```

Point at the `model.safetensors` line: "matches the hub's LFS record (not downloaded)".

Say: this is our signed list of every file in Qwen2.5-0.5B-Instruct at one exact
commit. Hugging Face publishes a SHA-256 for every large file, so a gigabyte of
weights is checked without downloading it. Anyone can run this.

## 1:20 The whole reference, checked from outside (50 s)

```bash
tvc verify-reference --registry reference/registry.jsonl \
  --profile dc7d054fbd75b6c74055ab3e6c074c5a28e3606296e0a3afce05372a92616374 \
  --publisher 8f738e4f8e4b3ce2b820dcc9cea88635f0992a56f23eccbc4b5a8d968db421cd
```

Say: this is a real run, on this laptop's CPU, of Ollama's 4-bit build: twelve secret
test prompts, three samples each. The prompts aren't published. If they were, a
provider could spot them and route only those to the real model. What's published
is a sealed commitment to them, and nine checks that it's all signed, intact, and
consistent. Note that the 4-bit build has a different manifest from the Hugging
Face files. That's the quantised-copy case SPOT exists to catch.

## 2:10 Opening one sealed prompt (40 s)

```bash
tvc verify-reveal --registry reference/registry.jsonl --set outputs \
  --run 8ca35b9b7b16f5968a713efbed9f2c00dc080ee46cb65085318df909756123d5 \
  --reveal reference/reveals/output-18.json
```

Say: when a provider disputes a verdict, we open just the prompts in question.
This one asked for the capital of Australia, and the real model said "Sydney". It's
wrong, and it's still the right reference: a provider that answers "Canberra" isn't
serving this model.

## 2:50 It existed by a known time (30 s)

```bash
tvc verify-anchor --registry reference/registry.jsonl
```

Say: the ledger head went to the OpenTimestamps calendars on 1 October and from
there into a Bitcoin block. Signatures can't prove we didn't change our reference
later, because we hold the key. A Bitcoin timestamp can. Read out the block height
and show the merkle root matching on a block explorer if the proof has upgraded.
If it still says pending, say so.

## 3:20 Trying to cheat (40 s, last on purpose)

```bash
tvc demo
```

Scroll to step 6. Five attempts, five refusals:
- an easier prompt swapped in after the fact;
- a prompt moved to another position;
- one weight changed out of 96;
- a run citing a setup that wasn't published yet;
- someone else's key.

Say: each of these is a way a checker could quietly move the goalposts. Each one is
refused, and the refusal says exactly why.

## If there's time

`tvc verify-reference ... --json` shows the same checks as machine output for SPOT's
dashboard. And the 4-bit Qwen run took 31 seconds on a 2019 laptop CPU, so this
doesn't need special hardware to try.
