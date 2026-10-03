# How W-TVC works, end to end

W-TVC is the open protocol behind authenticated.si's provider checks. authenticated.si keeps its test prompts secret so providers can't game them. W-TVC publishes sealed fingerprints of those tests, the thresholds and every verdict, so anyone can check them later without seeing a single prompt.

## 1. Where it's used

```mermaid
flowchart LR
  HF["Open weights<br/>on Hugging Face"]
  subgraph PRIV["authenticated.si (private)"]
    REF["Reference run on our GPU<br/>secret test prompts"]
    HON["Honest variants<br/>same weights, other settings"]
    CAL["Calibration<br/>a threshold per test"]
    AUD["Daily audit of each provider"]
    REF --> CAL
    HON --> CAL
    CAL --> AUD
  end
  PROV["Providers<br/>OpenRouter and others"]
  subgraph PUB["W-TVC ledger (public)"]
    LED[("Signed, hash-chained records<br/>fingerprints and numbers only")]
  end
  BTC[("Bitcoin<br/>via OpenTimestamps")]
  CUST["Customer<br/>paid health board"]

  HF --> REF
  PROV -- "answers to drawn prompts" --> AUD
  REF -- "manifest, setup, sealed roots" --> LED
  CAL -- "thresholds, measured power" --> LED
  AUD -- "draws, statistics, verdict" --> LED
  LED -- "ledger head" --> BTC
  AUD -- "verdict and audit id" --> CUST
  CUST -- "tvc verify-audit" --> LED
  HF -. "tvc check-hf" .-> LED
```

## 2. One day in the life of a provider check

```mermaid
sequenceDiagram
  autonumber
  participant S as authenticated.si
  participant L as W-TVC ledger
  participant B as Bitcoin
  participant P as Provider
  participant C as Customer
  S->>L: publish reference, honest set, calibration
  L->>B: anchor the ledger head (OpenTimestamps)
  Note over L,B: the thresholds now provably exist
  S->>S: draw prompts from the sealed pool<br/>(fixed by endpoint, date, battery)
  S->>P: send the drawn prompts
  P-->>S: answers
  S->>S: statistic vs threshold, T0 gate, verdict
  S->>L: publish the audit (statistics, verdict, sealed answers)
  S-->>C: verdict on the health board
  C->>L: tvc verify-audit
  L-->>C: calibration came first, prompts not picked,<br/>verdict follows from the numbers
  opt dispute
    S->>C: reveal one answer with its Merkle proof
    C->>L: verify-audit --reveal
  end
```

## 3. The documents and how they cite each other

Every arrow is a SHA-256 the document carries and the signed ledger claim repeats.

```mermaid
flowchart BT
  MAN["weights-manifest/v1<br/>every file: path, size, sha256"]
  SET["reference-setup/v2<br/>engine, kernels, GPU, seed, harness"]
  BAT["battery/v1<br/>sealed prompt pool, draw size,<br/>statistic code digest"]
  RUN["reference-run/v2<br/>sealed outputs root"]
  HON["honest-set/v1<br/>honest variants of the same weights"]
  CAL["calibration/v1<br/>threshold per test and budget,<br/>honest false-positive rate, power"]
  AUD["audit/v1<br/>endpoint, window, draws,<br/>statistics, verdict"]
  PRO["profile/v2<br/>one model's reference"]

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

## 4. What is public and what stays private

| Public, in the ledger | Private, at authenticated.si |
|---|---|
| Which weight files the reference used, with their hashes | The test prompts |
| How the model was run (engine, kernels, GPU, seed) | The reference model's answers |
| A salted Merkle root of the prompts and of the answers | The salts that open those roots |
| Each test's thresholds, honest false-positive rate and measured power | The battery code and the prompt generators |
| Each audit's drawn indices, statistics and verdict | Per-provider history on the paid health board |
| A Bitcoin timestamp on all of the above | |

A single prompt or answer is only opened, with a Merkle proof, when a verdict is disputed. Once opened, it's retired.

## 5. Why thresholds come from honest variants

The same weights served with different kernels, batch sizes or precision give measurably different answers. A plain significance test flags every honest provider. So each threshold is set from honest variants of the same weights, and published with the false-positive rate it gives.

Rejection rate of one calibrated test on Qwen2.5-7B at 10 samples per prompt (from calibration `a72fe242` in `reference/objects/`):

```mermaid
xychart-beta
  title "How often each endpoint is flagged (Qwen2.5-7B, 10 samples per prompt)"
  x-axis ["Honest (mean)", "GPTQ int8", "fp8 W8A8", "AWQ 4-bit", "Qwen2.5-3B", "Qwen2-7B", "System prompt"]
  y-axis "Flagged" 0 --> 1
  bar [0.08, 0.05, 0.95, 1, 1, 1, 1]
```

Honest variants are flagged about 8% of the time. A 4-bit copy, a smaller sibling, the previous generation and an injected system prompt are flagged every time. An 8-bit weight-only copy can't be told from honest serving, and the calibration says so in `cannot_detect`. The injected system prompt is also caught by the prompt-token check, which turns the verdict into "misconfigured" instead of "different model".

## 6. What a verifier needs

- The public ledger: `reference/registry.jsonl`, `reference/objects/` and `reference/anchors/`.
- The publisher's 32-byte key, pinned from somewhere you trust.
- `tvc`, built from this repository.
- Optionally, network access to Hugging Face (`check-hf`) and the OpenTimestamps calendars (`verify-anchor`).

No GPU, no account and no access to authenticated.si.
