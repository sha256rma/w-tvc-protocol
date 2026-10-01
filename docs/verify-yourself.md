# Check the Qwen reference yourself

This walks through every claim the reference in `reference/` makes, in the
order you'd want to check them, with commands you can paste. You need a clone of
this repository and a Rust toolchain (1.85 or later). Step 5 also needs Ollama.
Nothing here needs a GPU or any trust in us.

Build once:

```bash
cargo build --release --bin tvc
alias tvc=./target/release/tvc
```

## 0. The claim, in plain words

On 2 October 2026 a publisher (key `8f738e4f8e4b3ce2b820dcc9cea88635f0992a56f23eccbc4b5a8d968db421cd`)
ran Qwen2.5-0.5B-Instruct on twelve test prompts and recorded what it said. They
published:
- exactly which weight files they used;
- how they ran them;
- a sealed commitment to the prompts and answers.

Then they timestamped all of that on Bitcoin. The prompts stay sealed until someone
has a reason to open one. Prompt 6 has been opened as an example.

## 1. The published files are what they say they are

Every document lives in `reference/objects/` under its own SHA-256. You don't need
our code for this step:

```bash
cd reference/objects
for f in *.json; do [ "$(shasum -a 256 "$f" | cut -c1-64).json" = "$f" ] && echo "ok $f"; done
cd ../..
```

Six lines of `ok` means no published document has been edited.

## 2. The ledger is intact and every record is signed

```bash
tvc audit --registry reference/registry.jsonl
tvc verify-reference --registry reference/registry.jsonl \
  --profile dc7d054fbd75b6c74055ab3e6c074c5a28e3606296e0a3afce05372a92616374 \
  --publisher 8f738e4f8e4b3ce2b820dcc9cea88635f0992a56f23eccbc4b5a8d968db421cd
```

`audit` re-derives every record's digest and lists the six records in order.
`verify-reference` follows the working profile to its run, setup and weights
manifest, and checks that each one is signed by the key above. Try it with any
other `--publisher` and it fails with exit code 3.

## 3. The weights are the public Qwen release

The skeleton profile's manifest names the Hugging Face repository and commit.
This compares every file in it with what Hugging Face publishes at that commit:

```bash
tvc check-hf --manifest reference/objects/3f976cbf5f3e4ad9b15f23c1a16987851be036b2179d1025e983f4c68b2cf82c.json
```

The 988 MB `model.safetensors` is checked against the hub's own SHA-256 record
and isn't downloaded. The small files (config, tokenizer, licence) are
downloaded and hashed. You can also check by eye: open
`https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct/blob/7ae557604adf67be50417f59c2c2f167def9a775/model.safetensors`
and compare the SHA256 shown there with `fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe`.

## 4. An opened prompt was in the sealed set from the start

```bash
RUN=8ca35b9b7b16f5968a713efbed9f2c00dc080ee46cb65085318df909756123d5
tvc verify-reveal --registry reference/registry.jsonl --run $RUN --set prompts --reveal reference/reveals/prompt-6.json
tvc verify-reveal --registry reference/registry.jsonl --run $RUN --set outputs --reveal reference/reveals/output-18.json
```

Prompt 6 is "What is the capital of Australia? Answer with one word." The model
answered "Sydney.", which is wrong. The reference keeps the model's real answer,
because that's what a provider serving the real model should return.

Now edit one character of the prompt inside `prompt-6.json` and run the first
command again. It fails: the sealed root only opens for the exact bytes that were
sealed, at index 6, with that salt.

## 5. Re-run it yourself

The working profile says the run used Ollama's `qwen2.5:0.5b`. Pull it and confirm
it's the same file:

```bash
ollama pull qwen2.5:0.5b
ls ~/.ollama/models/blobs/ | grep c5396e06af294bd101b30dce59131a76d2b773e76950acc870eda801d3ab0515
tvc show --registry reference/registry.jsonl --digest 1fc98d376753deca1507e4f8a1d810f55494df0b1696b6509354cabea192791e
```

Ollama names every blob by its SHA-256, so the `grep` finding the file is the
check. `show` prints the manifest, and `model.gguf` in it has that same digest.

Then ask the opened prompt with the published settings (temperature 0, seed 42,
128 tokens):

```bash
ollama serve &   # if it isn't running
printf '%s\n' "$(python3 -c "import json;print(json.dumps(json.load(open('reference/reveals/prompt-6.json'))['item']))")" > /tmp/p.jsonl
python3 reference/run_ollama_reference.py /tmp/p.jsonl /tmp/o.jsonl --model qwen2.5:0.5b --samples 1
```

On our machine (Intel i9-9980HK, CPU only, Ollama 0.24.0) every one of 36 runs
reproduced byte for byte. On other hardware or another Ollama version the answer
can differ in wording. That's why SPOT compares with bands rather than exact
bytes, and why a two-GPU determinism test is on the roadmap.

## 6. It all existed by a known time

```bash
tvc verify-anchor --registry reference/registry.jsonl
```

The ledger head `0fd0507322517e947c24fe2b40fa9fcdc63ca7318d085de50180bd3a52ee4a0b`
was submitted to the OpenTimestamps calendar at 2026-10-01 19:51 UTC. For the
first few hours this prints `pending`. After that, the command fetches the
upgraded proof, saves it, and prints a block height and a merkle root. Open that
block on any block explorer and compare the merkle root. If they match, every
record in the ledger existed before that block was mined.

## What this doesn't show

The setup record is the publisher's description of their own run. Nothing here
proves they used that engine or that CPU. What's fixed is the description, so step
5 can hold them to it. The answers in the output set are what the publisher says
the model said. Steps 4 and 5 are how you hold them to that, one opened prompt at
a time.
