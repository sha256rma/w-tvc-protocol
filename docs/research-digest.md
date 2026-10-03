# Research digest: verifying what model an LLM endpoint serves

State of research and practice as of October 2026. For each paper, article and project this lists what the method does and the numbers that matter. It is built from the four files in `research_notes/LLM endpoint reference tests/` (each number there is cited to a table or section), the literature review in `docs/reference-tests-literature.md`, and our own GPU runs. Where a number came from a summarizing web fetch rather than the source, it says so.

## The short version

- **The problem is real and measured.**
  - 45.83% of 24 shadow-API endpoints failed an identity check (Real Money, Fake Models).
  - 44% of 75 OpenRouter endpoints add tokens to the official chat template (AgentProv).
  - Kimi's verifier found tool-call schema accuracy ranging from 100% to 71.96% across providers of the same model.
  - B3IT and Log Probability Tracking caught 8 and 37 silent changes on live OpenRouter endpoints.
- **Five families of technique exist:**
  1. black-box statistical tests against a reference (MET, RUT, One Token, IRIS, Ventor-QTest, AgentProv, KBF);
  2. change detectors that compare an endpoint with its own past (B3IT, LT, "You've Changed");
  3. fingerprint classifiers (LLMmap, Idiosyncrasies, n-gram stylometry);
  4. logprob geometry (model image, ellipse signature);
  5. cryptographic or hardware proofs (TEEs, zkLLM, CommitLLM, TopLoc, SVIP).
- **What tests catch:**
  - A different model is easy: AUROC 0.97–1.00 with a few dozen to a few hundred queries.
  - 4-bit is usually caught.
  - 8-bit or fp8 on a 7B model is usually invisible, because honest serving noise is as large as the quantization signal.
  - Low-rate routing to a close relative is the hardest case.
- **False accusations are the binding constraint.** Honest providers of the same weights differ: greedy agreement across real APIs is under 5%, IRIS separates 14 of 15 honest same-model provider pairs, and MET falsely flags 67% of endpoints that only add a system prompt. Every serious paper now calibrates against a measured honest null.
- **Nobody publishes verifiable results.** Kimi's verifier, OpenRouter Exacto, openbenchmarks and the academic audits publish mutable tables or dashboards. None commits to its test set before testing, signs results or timestamps them. That gap is what W-TVC fills.

## 1. Evidence that substitution and misconfiguration happen

| Source | What they did | Numbers |
|---|---|---|
| Real Money, Fake Models (Zhang et al., arXiv 2603.01919) | Audited 17 shadow APIs used in 187 papers; LLMmap fingerprints, 100 queries per endpoint | 45.83% of 24 endpoints fail identity verification, 12.50% more show large deviations. Gemini-2.5-flash on MedQA: 83.82% official vs about 37% on shadow APIs. One "GPT-4o-mini" matched Qwen2.5-7B. Testbed: LLMmap 96% accuracy (3% FPR, 5% FNR), MET 88.33% (4.67% FPR, 18.67% FNR) |
| AgentProv (CISPA, arXiv 2609.00052) | Prompt-token counts on 75 OpenRouter endpoints | 44% deviate from the official template count. Nine add a constant offset (+25 tokens on Llama-3.2-3B, +12 Mixtral-8x22B, +7 Gemma-3n) |
| Kimi K2 Vendor Verifier (MoonshotAI/K2-Vendor-Verifier) | 4,000 tool-call requests per provider vs the official API | K2-0905 schema accuracy: Moonshot, DeepInfra, Fireworks, NovitaAI 100%; Together 71.96%, AtlasCloud 72.44%, Baseten 72.49%. Groq (trigger 69.52%) and Nebius (50.60%) under the 80% threshold. K2-thinking: Chutes 68.10% trigger, NovitaAI 72.22%, under 73% |
| vLLM blog on Kimi K2 (Oct 2025) | Root-caused the K2 failures | Under 20% of tool calls parsed (218 vs 1,286 official). Three serving bugs: dropped `add_generation_prompt`, mangled empty content, strict tool-call-ID parser. After fixes 1,007 of 1,325, 76% |
| B3IT (Chauvin et al., ICML 2026, arXiv 2602.11083) | Daily border-input monitoring of 131 OpenRouter endpoints | 8 changes in 23 days; one confirmed by Together's changelog (Mistral-7B-v0.3 redirected to Ministral-3-14B). Cost $0.52 per endpoint per year |
| Log Probability Tracking (Chauvin et al., ICLR 2026, arXiv 2512.03816) | 189 endpoints monitored for 4 months | 37 changes (0.86 per endpoint-year), 34 of them on open-weight models. Only 23% of OpenRouter endpoints return logprobs |
| MET real audit (Gao et al., ICLR 2025, arXiv 2410.20247) | 31 Llama endpoints from 9 providers, summer 2024 | 11 of 31 flagged. Cost per audit $0.14 on the dearest endpoint |
| Ventor-QTest (Tencent Zhuque Lab, arXiv 2608.16391) | DeepSeek V4 Flash, official API vs 6 third-party routes | Official self-check passes (Holm p = 0.515); all 6 routes reject (p = 0.00035), including the declared-FP8 DeepInfra route. On DigitalOcean, Terminal-Bench pass rate fell from 82.6% to 13.6% across exposure quartiles (exploratory) |
| openbenchmarks-labs/inference (Sep 2026) | 600 paired requests per provider, GLM 5.3 Flash, 10 providers, T=0 | Exact task success 84.83% (Nebius, 14.83% operational failures) to 99.50% (Fireworks, Telnyx). Corpus private |
| OpenRouter Exacto and Auto Exacto (blog, Oct 2025, Mar 2026) | Routes to providers with better tool-call telemetry | Tool-call error drops after routing: GLM-5 −88%, GLM-4.7 −80% (about 8% to 1%), gpt-oss-120b −36% (5.6% to 3.5%), DeepSeek V3.2 TauBench 69% to 74%. Full data held back for provider review |
| Your Agent Is Mine (arXiv 2604.08407) | 28 paid and 400 free API routers | 1 paid and 8 free routers injected malicious code into tool calls; 17 touched canary AWS credentials; 1 drained ETH. Decoys drew 2B billed tokens and 99 leaked credentials |
| Zenodo divergence study (Chandra & Reddy, Zenodo 20320651) | 3,564 T=0 completions, 7 open models, 22 provider-model pairs | 0% exact agreement across providers on creative tasks; 66–100% semantic agreement on factual and arithmetic, 30–70% on code. On GPT-OSS-20B, 2 of 3 providers returned empty visible output for short prompts |

## 2. Black-box reference tests (auditor's own reference vs the endpoint)

### MET, MMD with a Hamming kernel (Gao, Liang, Guestrin; ICLR 2025; arXiv 2410.20247)
- **Technique:** two-sample kernel MMD between reference and endpoint completions (25 prompts, 50 tokens, T=1); p-value from a simulated null.
- **Power:** median 77.4% across quantization and watermark alternatives at 10 samples per prompt. Llama-3.1-8B: nf4 1.00, int8 0.08. Llama-3-8B int8 0.79. 70B int8 1.00. Raising samples from 10 to 50 per prompt lifts Llama-3-8B int8 from 0.30 to 0.96, at under $5 per audit.
- **Honest null:** fp16 vs fp32 power 0.00–0.04. Under an added system prompt the FPR is 67% (AgentProv).
- **Composite null:** reject only if the endpoint fails against every honest variant (intersection-union).
- **Licence:** code has no licence file.

### RUT, rank-based uniformity test (Zhu et al.; ICLR 2026; arXiv 2506.06975)
- **Technique:** rank each endpoint sample among 100 reference samples by log-rank score under the reference model, then test uniformity with Cramér–von Mises. Needs reference logits; one API call per prompt.
- **Power AUC over substitution fraction:** 4-bit Gemma-2-9B 0.392, Llama-3.2-3B 0.642, Mistral-7B 0.586; 8-bit 0.049 / 0.132 / 0.049. "None of the methods succeed in reliably detecting … 8-bit." Hidden jailbreak system prompts 0.858–0.895. Full swap 0.818–0.895.
- **Honest null:** A6000 vs A100 rejection 0.058–0.094. Real providers: Llama-3.2-3B on Nebius 0.962, Novita 0.988.
- **Licence:** MIT.

### One Token Is Enough (Bruckner; arXiv 2607.10252)
- **Technique:** distribution of one-word answers to trivial prompts (10 tasks × 4 languages), compared by Jensen–Shannon divergence.
- **Results:** over 165 OpenRouter models, AUC 0.971 and EER 7.3% with the full battery; EER 10.6% with 8 cells (about 100 queries). Full census of 326,047 responses cost $34.44 ($0.21 per model). Family attribution 59.5% vs 18.4% chance.
- **Honest null:** split-half floor 0.140, cross-provider median 0.227, impostor median 0.463. 29% of same-model provider pairs land beyond the impostor 5th percentile. A reference from another provider drops AUC to 0.880.
- **Gap:** no controlled quantization test.
- **Implementation:** ToseaAI/llm-fingerprint-detector, an MIT TypeScript port with 11 bundled references and thresholds 0.25 / 0.35. Its claim to catch quantization is unvalidated.

### IRIS, random-string probes (Zhang, Zhang, Qin; arXiv 2607.20860)
- **Technique:** ask for random bits or digits; 179 string features; a random forest scores "tells"; the budget is fixed in advance from a pilot.
- **Substitution:** AUROC 0.993 at 1 query and 0.9997 at 8 on a Qwen3 ladder. MET gets 0.111 and 0.993 there, RUT 0.634 and 0.726.
- **Dilution:** routing at 5 / 10 / 20 / 40% is caught in about 64 / 32 / 16 / 8 queries. A deployed 80-query audit at 30% routing: power 0.85, FPR 0.017. Required queries ≈ ln(1/δ)/(ε·q).
- **Quantization:** q4 vs fp16 on Qwen3-0.6B, tell rate 0.42 (about 72 queries at 10% routing); 0.74 at 1.7B, 1.00 at 4B. A low-entropy probe gets only 0.06.
- **Honest null:** honest-pair FPR median 0, mean 0.017, 95th percentile 0.090, max 0.557. After switching to an exact binomial test with a Clopper–Pearson bound: 95th percentile 0.018, pooled 0.0065. 14 of 15 same-model provider pairs are distinguishable; two providers that both declare fp8 mistral-nemo separate at AUROC 1.00.
- **Licence:** non-commercial.

### Ventor-QTest (Tencent Zhuque Lab; arXiv 2608.16391)
- **Technique:** 12 frozen one-token-choice contexts, 50 samples each, bias-corrected KL against reference probabilities, a parametric null and Holm correction across routes.
- **Cost:** $0.0033 per 600-call route.
- **Power planning:** 90% power at KL δ = 0.03 needs 52 samples per context; δ = 0.01 needs 159.
- **Limit:** the authors say a rejection shows inconsistency, not which change caused it.
- **Licence:** Apache-2.0 (parent repo).

### AgentProv, tool-choice probes (CISPA; arXiv 2609.00052)
- **Technique:** which of several equivalent tools the model picks; permutation null; 20 templates × 50 queries, well under $1.
- **Results:** all 630 cross-checkpoint pairs rejected, 0 of 36 self-pairs. False positives under an injected system prompt: AgentProv 7%, MET 67%, RUT 53%, LLMmap 20%. On 9 real endpoints AgentProv accepted 7, MET 1, RUT 2.
- **Quantization:** 8-bit Qwen2.5-7B and Llama-3.1-8B accepted by all three tests.
- **Partial routing:** routing is caught only while 30–40% or less of traffic goes to the genuine model.
- **Code:** not released.

### KBF, knowledge-boundary fingerprints (Fang et al.; arXiv 2605.29524)
- **Technique:** T=0 numerical-recall probes with a Clopper–Pearson binomial test, on 16 production endpoints.
- **Results:** 155 of 155 substitutions flagged, 0 of 16 same-model false positives, 0 of 30 under role prompts, temperature and RAG wrappers, 2 of 80 in agent configs. Catches 5–10% routing for well-separated pairs; the hardest pair needs about 43%. $0.02–0.24 per audit.
- **Gap:** no quantization test.

### Berkeley substitution audit (Cai, Shi, Zhao, Song; arXiv 2504.04715)
- Text classifiers separating FP8 or INT8 copies from originals score 48.7–51.65%, which is chance. Identity prompting reveals quantization under 5% of the time.
- MMD on INT8 never rises above α at 8B. At 70B it rejects reliably only when 60% or more of traffic is substituted.
- Greedy agreement of Gemma-2-9B across provider APIs is under 5%, and honest divergence "is often larger than that induced by quantization."
- Recommends TEEs. Code MIT.

### FLIPS (Richardeau et al.; ICML 2026; arXiv 2606.03330)
- Instance-level fingerprints from biased random binary sequences, designed to tell system prompt, sampling config and quantization apart.
- 96% closed-set and 90% open-set accuracy over 237 instances. Full text not read, so there are no per-alternative numbers.

### Other 2026 work noted
AdaptPrint (2608.22213), prefix-cache side channels in reseller chains (2608.20732), a four-stage anonymous-model audit (2608.31142), and benbenlijie/llm-provider-audit (a Python CLI with reference variance calibration and negative controls; synthetic examples only).

## 3. Change detectors (an endpoint against its own past)

These assume the reference comes from the same serving stack, so their low false-positive rates do not carry over to a self-hosted reference.

| Method | Technique | Numbers |
|---|---|---|
| B3IT (2602.11083) | Prompts whose top two tokens are tied; flags a first token never seen before | ROC AUC 0.9 at $2.2/yr vs MET 0.61 at equal cost. Border inputs found on 73–78% of 131 endpoints. Fails where reasoning is hidden |
| LT (2512.03816) | One output token, top-k logprobs, permutation test | AUC 0.915 vs MET 0.670; $0.14/yr vs $146/yr; 2–3 orders of magnitude more sensitive than MET on pruning |
| You've Changed (2504.12335) | K-S tests on text features (perplexity, sentiment, word count) with Bonferroni or Fisher | Detects a 3% mixture of two very different models with 22,000 items; catches system-prompt injection at p = 4.8e-26 on 3,000 reviews |

## 4. Fingerprint classifiers and logprob geometry

| Method | What it identifies | Numbers |
|---|---|---|
| LLMmap (2407.15847) | Model version from 8 active probes | 95.3% closed-set over 42 versions; 81.2% on unseen models. Blocking two query classes cuts accuracy by more than half |
| Idiosyncrasies (2502.12150) | Which chat API wrote a text | 97.1% on 5 APIs; Qwen2.5 sizes 59.8% (4-way); same model, different sampler 50–59.6% (near chance) |
| Natural Fingerprints (2504.14871) | Training-run differences | 85.0% on six 7B families; same data, different seed still 46.1% vs 33.3% chance |
| N-gram stylometry (2405.14057) | Model family | F1 0.927–0.960; within a family nearly indistinguishable |
| RAFP rare-prompt fingerprints (2505.12682) | Lineage and ownership | TPR 93–100%, survives fine-tuning. Built to survive 8-bit, so it cannot detect it. Hash-commits fingerprints and reveals only in a dispute |
| Model image (2403.09539) | Exact checkpoint from full logprobs | Under $1,000 for gpt-3.5-turbo; needs logit bias |
| Ellipse signature (2510.14086) | Exact model head from one full logprob vector | Separates models "by several orders of magnitude"; forging a 70B-class head costs about $16.5M for closed weights. Quantization does not show, because the head is usually not quantized |

**Spoofing.** GhostPrint (2606.16100) LoRA-tunes a weak model to pass LLMmap (up to 95% attack success), Idiosyncrasies (up to 96.7%) and MET (23–60%, the hardest). The attacker knows the method and the query distribution but not the exact queries. Nasery et al. (2509.26598) fully bypass ten ownership-fingerprint schemes. The lesson is that public or reused probes can be gamed, and sealed, rotated probes compared against a full distribution resist best.

## 5. How much honest serving moves outputs (the false-positive problem)

| Source | Honest change | Effect |
|---|---|---|
| Silent Hyperparameter (Pape et al., 2605.19537) | 5 inference engines, same weights, one H100 | Up to **16.6 benchmark points** (DeepSeek-R1-Distill-Qwen-7B GSM8K: 78.47 vs 61.87 on Ollama). Causes: BOS injection (+4.70 to +8.34 when removed), hidden repetition penalty 1.1 (+11.67). Kernels, prefix caching and CUDA graphs each under 1 point |
| Masoudian et al. (2608.04714) | 5 frameworks, small models | Backend explains about 39% of out-of-the-box variance; vLLM 0.8.5 defaults to T=1.0 and max_tokens 16 |
| Du et al. (2609.26621) | BF16 vs FP16, same GPU, greedy | 49–100% of prompts produce different text. Code execution still agrees on 97.6% while tokens agree on 26.2% |
| Cooper et al. (2609.25624) | A100 vs L40S vs H100, BF16 greedy | 30.81–100% of problems diverge on some GPU pair; batch composition alone 6–25%. Fixed-order FP32 GEMMs make linear layers bitwise identical across GPUs |
| Yuan et al. (2506.09501) | Batch size, GPU count, GPU type | Up to 9% accuracy variation and 9,000-token differences in reasoning length |
| Thinking Machines (blog) | 1,000 T=0 completions of Qwen3-235B | 80 unique completions by default; 1 with batch-invariant kernels. Cause: server load changes batch size |
| Vosti (2609.38981) | Bitwise tests of vLLM and SGLang | Default vLLM matches bitwise on 177 of 296 batch variations. Deterministic modes pass on Llama-3.1-8B, fail partly on Gemma3-4B |
| Batch-invariance cost | vLLM `VLLM_BATCH_INVARIANT=1` | 54–67% throughput loss at CUDA-graph batch 1–64 (third-party, RTX 4090). CoRun gets determinism with 15–324% more throughput |
| Cross-provider | Same model, different providers | Greedy agreement under 5% (Berkeley); IRIS separates 14 of 15 honest pairs; One Token cross-provider AUC 0.880 |
| Chat template dates | Llama-3.2 template embeds today's date | Up to 37.60% apparent divergence when a sweep crossed midnight |
| Leading whitespace | HF Inference dropped a space | MET power 1.00 against an honest endpoint; 0.211 after the fix |

**How papers set thresholds without accusing honest providers:**
- MET: intersection-union over honest variants.
- IRIS: a quantile threshold from a calibration split, plus an exact binomial test with a Clopper–Pearson bound.
- Ventor: a parametric null with Holm correction.
- AgentProv: a within-template permutation null.
- One Token: impostor percentiles.
- Richter et al. (2410.19406): anytime-valid e-processes for continuous auditing.

## 6. Quantization: what output changes to expect

| Source | Numbers |
|---|---|
| Red Hat / IST (Kurtic et al., 2411.02355) | Benchmark recovery at 8B / 70B / 405B: FP8 99.31 / 99.72 / 100.12%; INT8 100.31 / 99.87 / 99.32%; INT4 98.72 / 99.53 / 99.98%. Greedy text still differs: ROUGE-L vs BF16 0.51 (FP8, 8B), 0.41 (INT4, 8B) |
| Accuracy Is Not All You Need (Dutta et al., 2407.09141) | MMLU answers flipped vs 16-bit: GPTQ W8A16 0.26–1.05%; BnB W8A8 2.5–4.2%; 4-bit 4–10.7%. KL: W8A16 7.9e-5, W4A16 0.02. KL and flips correlate (Spearman 0.981) |
| llama.cpp k-quants (Kurt, 2601.14277) | Llama-3.1-8B average: F16 69.47, Q8_0 69.41, Q4_K_M 69.15, Q3_K_S 65.49 |
| LLaMA3 quantization (Huang et al., 2404.14047) | 4-bit costs about 2%; 8-bit near lossless at 8B and 70B |
| Exploiting quantization (Egashira et al., 2405.18137) | Weights can be tuned to be benign in full precision and malicious once quantized: content injection 0.13% fp32 vs 74.5% int8 on Gemma-2b. Precision should be pinned in a reference, not only the checkpoint |

## 7. Cryptographic and hardware approaches

| Approach | What it proves | Cost | Catch |
|---|---|---|---|
| NVIDIA confidential computing (Hopper, Blackwell) | GPU firmware and driver integrity | H100: under 7% for most queries, −0.13% at 70B, TTFT +19% at 8B (2409.03992). B200 + TDX: 1–3% when tuned, 30–40% on stock stacks (2608.26575) | GPU attestation does not cover weights. Binding needs a measured CPU-TEE container that pins the weights hash |
| TEE serving per Cai et al. (2504.04715) | Hashes of loaded model and code | +9–16% first-token latency, −3 to −15% throughput on H100 | Provider must opt in |
| Phala / RedPill on OpenRouter | GPU + Intel TDX attestation, enclave-signed responses | Under 7% claimed | Weights binding depends on the container measurement (not verified in primary docs) |
| zkLLM (2404.16109) | Correct inference, parameters private | 13B: 803 s prover, 188 kB proof, 3.95 s verify on one A100 | Far too slow to serve |
| zk-SNARK adversarial probes (2608.27954) | Logits on hidden committed probes stay within allowed drift | 1.0–1.8 s prove, 0.84 s verify | Breaks if the provider learns the probes. Closest academic design to SPOT |
| opML (Ora) | Optimistic fraud proofs | About native speed | Needs one honest challenger |
| CommitLLM (Lambda Class) | Commitment to weights, quantization, template, decode policy; per-response receipts | 12–14% generation overhead, about 1.3 ms per challenged token (blog numbers) | Provider opt-in |
| TopLoc (2501.16007) | Locality-sensitive hash of activations | 258 bytes per 32 tokens, validation up to 100× faster than inference | Verifier recomputes with the claimed model |
| SVIP (2410.22307) | Secret proxy task on returned hidden states | FNR 3.49%, FPR under 3%, under 0.01 s per prompt | Trusted third-party platform |
| Signed response envelopes (2604.08407) | DKIM-style provider signature on each response | Proposed | Not deployed by any major provider; trustedrouter-provider-check already tests signed receipts |

## 8. Deployed verifiers and tools

| Project | What it checks | Notes |
|---|---|---|
| Kimi K2 Vendor Verifier | Tool-call trigger F1 and schema accuracy vs the official API, 4,000 requests | Threshold from repeated official runs (">73%", ">80%"). About 50% of the test set public. README table, edited in place |
| Kimi Vendor Verifier (six checks) | API parameter enforcement, OCRBench, MMMU Pro, AIME2025 avg@32 (98.4 official), K2VV tool calls, SWE-Bench | Promises a public leaderboard; none seen |
| meta-llama/llama-verifications | Functional tests (100% expected) and benchmarks vs the model card | Llama API: −0.44% average vs card |
| trustedrouter-provider-check | Six-tier OpenAI-API contract conformance, including signed receipts | "Point-in-time test evidence, not certification." No model-identity test |
| fallrisk.ai | Top-k logprob gaps, 10 prompts × 3 sessions | 119 of 120 correct across 6 models for $0.72 (summarizing fetch) |
| Strake | Teacher-forced scoring of a fixed sequence via logprobs | Same model at two quantizations drifts about 0.07 nats/token; a 2× cheaper impostor shows +0.27, a 6× cheaper one +0.66. 10–15 challenges detect a 2× substitution. Needs logprobs |
| OpenRouter Exacto | Quality-first routing from tool-call telemetry | Dashboard only; data held back for provider review |
| ToseaAI/llm-fingerprint-detector | One Token JSD, TypeScript | MIT; quantization claim unvalidated |
| benbenlijie/llm-provider-audit | Reference variance plus negative controls | Synthetic examples only |

## 9. What our own GPU runs found (vLLM 0.30, L4 and A100)

| Model | Result |
|---|---|
| Qwen2.5-7B-Instruct (L4) | With plain p-values, MET flagged all 5 honest serving variants at p = 0.001. With thresholds at the 95th percentile over the honest set, honest variants were flagged 6–10% of the time. AWQ 4-bit, a 3B sibling and Qwen2-7B caught 100% even at 5 samples per prompt. fp8 W8A8 caught 95% at 10 per prompt. GPTQ int8 weight-only invisible. The token-count check caught an injected system prompt and the Qwen2 template |
| Qwen3.5-9B (A100) | Honest variants flagged 0–25% (mean about 7%). The 4B and Qwen3-8B substitutes and thinking-on caught 100%. 20% routing to Qwen3-8B caught 100% by both text tests; 20% to the 4B, 0.85 and 0.60 |
| Determinism | Default kernels: 20 of 32 greedy answers identical on Qwen2.5-7B and Qwen3.5-9B; batch-invariant: 32 of 32. gpt-oss-20b: 1 of 32 with default kernels. Batch-invariant mode is unavailable for Qwen3.5 (linear attention) and gpt-oss MXFP4 on L4/A100 |

These match the literature: a different model is easy, 4-bit is caught, 8-bit weight-only is not, and the honest set decides whether a test is usable at all.

## 10. Where the field stands and where the gaps are

1. **Black-box tests work for gross substitution.** IRIS, One Token, KBF and AgentProv reach AUROC 0.97+ for a different model at under $1 per audit.
2. **8-bit on mid-size models is below the honest noise floor.** No paper detects it reliably at 7–9B from text. Treat it as out of scope, and say so.
3. **Thresholds must come from a measured honest set**, per test and per query budget, or honest providers get accused.
4. **Prompt-side changes (system prompts, templates, BOS) must be checked first.** A token-count check costs nothing and turns a would-be false accusation into "misconfigured".
5. **Public probe sets get gamed.** Sealed, rotated, hash-committed probes are the pattern RAFP, Ventor and the zk-probe paper point to.
6. **Cryptographic proof needs provider cooperation.** TEEs and CommitLLM-style receipts are the strongest evidence where a provider opts in. Black-box testing is the only option for everyone else.
7. **Results are not verifiable.** Kimi, OpenRouter, openbenchmarks and the papers publish editable tables. None commits to its tests and thresholds before testing, signs results or timestamps them. A signed, Merkle-committed, Bitcoin-anchored reference ledger (W-TVC) is the missing piece: it lets anyone check that the reference, the honest set and the thresholds existed unchanged before an audit, while the probes stay secret.
