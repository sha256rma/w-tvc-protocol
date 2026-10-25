# The open honest set

Status: design, October 2026. Nothing here is built yet.

A verdict of "altered" means an endpoint's answers fall outside everything honest setups of the same model produced. Today authenticated.si runs every honest setup itself. For Gemma-4-26B that's 23 runs on two engines (vLLM, SGLang) and two GPUs (A100, H100). Every setup a provider uses that isn't in that set is a way to wrongly flag an honest business.

This design lets anyone contribute an honest setup, and makes sure a dishonest provider can't use that to widen the threshold until its own copy passes.

## Two problems decide the design

**Secret questions.** Anyone who runs the questions on their own machine can read them. A provider that knows the audit questions can send just those to the real model and pass every audit while serving a cheaper copy. So sealed questions never go to an untrusted machine in plain text.

**Poisoning.** A provider could submit its FP8 setup labelled as an honest BF16 one, so the threshold rises until FP8 passes.

## Two batteries

- **The sealed audit battery.** As today: committed in the ledger, never revealed except one item at a time on dispute.
- **A public calibration battery per model.** It's built the same way (T0, T1, T3, T4) with different questions, and its reference answers are published. Anyone can run it and recompute its numbers. It screens contributions before anyone spends GPU time on them.

What we need from a contributor isn't their answers to the sealed questions. It's their *setup*, an exact, rebuildable recipe, plus evidence that it's honest. A second party then measures that setup on the sealed battery.

## Three ways a setup reaches the sealed battery

| Phase | Mode | How | Secret kept? | Proves what ran? | Hardware |
|---|---|---|---|---|---|
| 1 | Replay | A trusted runner rebuilds the setup and runs the sealed battery | Yes | Yes, the runner ran it | Anything rentable |
| 2 | Single-use slice | We query the contributor's endpoint with a fresh random slice of a large sealed pool, then retire and publish that slice | Only a small, used-up slice leaks | No | Anything |
| 3 | Confidential GPU | The contributor runs our harness in a confidential VM; questions are released only after attestation of the image and the weights | Yes, if the hardware holds | Yes, attested | H100, H200, B200 in confidential-computing mode |

Phase 2 needs two new pieces:
- **Large pools.** Thousands of questions per test, so slices never run short.
- **Per-question scoring.** Each question's statistic is divided by the reference's own noise on that question, so scores from different slices can be pooled. This needs validating on our own GPU runs before use.

## Admission

1. **Signed, exact setup.** A `reference-setup/v2` signed by the contributor: engine and version, lock file hash, GPU, driver, parallelism, every engine flag, request settings.
2. **Weights check.** The harness hashes the weight files against the reference's manifest. That's a claim on its own, and it's redone by the runner in a replay or attested in Phase 3.
3. **Public-battery screen.**
   - T0 must match: 8 of 8 token counts, or a documented one-token engine difference.
   - A broken run is refused.
   - A far-out run goes to review, because it may be new honest variation.
4. **Independent reproduction.** A second party's run must agree with the contributor's within the spread of two seeds of one setup. One party alone can't add a member.
5. **Known-fake guard.** Recompute the calibration with the candidate included. If a known fake that was caught before (FP8, 4-bit, smaller model, hidden prompt, thinking on) would now pass, the candidate goes to review with the numbers attached.
6. **One vote per setup.** Thresholds weight each distinct setup equally, so twenty copies of one setup count once.
7. **Published policy.** An `honest-policy/v1` per model lists what counts as honest. Judgment calls (FP8 KV cache, speculative decoding) are decided there in public.
8. **Signed decisions.** Every admission or refusal is a ledger record with its reasons, and can be appealed with more evidence.

Still not stopped:
- **A genuinely strange but honest stack** may widen the threshold. That's the point, and the cost shows up as lower, published power against known fakes.
- **Collusion between submitter and reproducer.** In Phase 1 SPOT is always one of the two. Later, reproducers are drawn at random, with the draw on the ledger.
- **A broken confidential-computing GPU.** A published break downgrades TEE runs to needing replay.

## Flow

1. Register a contributor key.
2. Run the public battery and sign a contribution.
3. Screen it.
4. Reproduce it: replay, slice or confidential GPU.
5. Run the known-fake guard.
6. Admit it on the ledger.
7. Recalibrate, publishing every member's statistics.
8. Audits logged after the new calibration use it. Earlier audits keep the one they cited, which `verify-audit` already enforces.

A flagged provider follows the same flow with its exact serving setup. If it reproduces as honest, the threshold moves for everyone and its next audit uses the new calibration. Past verdicts stand, with a note linking the new calibration.

## Reviewing the secret questions without leaking them

- **Commit now, reveal later.** Every sealed pool is committed before use. Retired slices and disputed items are revealed with proofs.
- **A named review panel.** Reviewers read a sealed pool under embargo and sign a `pool-review/v1` record saying it follows the published method and targets no provider.
- **A public generation method.** The recipe that generates questions is public, so a reviewer can generate their own pool and compare its statistics.

## Protocol changes

All additive: every published reference keeps verifying.

**Roles.** Today one key signs everything. A `key/v1` record binds a key to a role:
- **publisher:** references, policies, admissions, calibrations, audits;
- **contributor:** its own setups and contributions;
- **runner:** replays and confidential-GPU results;
- **reviewer:** pool and admission reviews.

`verify-reference` and `verify-audit` check that each document is signed by a key holding the role its kind needs.

**New kinds:**
- `key/v1` and `key-revoke/v1`;
- `honest-policy/v1`;
- `contribution/v1`, `replay/v1`, `attestation/v1` and `slice/v1`;
- `admission/v1`;
- `pool-retire/v1` and `pool-review/v1`;
- later, `reward/v1`.

**Changed kinds:**
- `battery/v2` adds `visibility` (public or sealed) and the generation recipe.
- `honest-set/v2` members cite an admission.
- `calibration/v2` adds per-setup weighting, every member's mini-audit statistics, power before and after, and a `supersedes` link.

**New commands:**
- `tvc contribute`: package a public-battery run and setup into a signed contribution.
- `tvc verify-contribution`: check a contribution's signature, setup, T0 and public-battery numbers.
- `tvc calibrate`: recompute thresholds from published statistics.
- `tvc admit`: record an admission decision.
- `tvc retire`: retire used question indices.

## Rewards, later

Rewards pay for coverage, never volume, and only after admission has a track record:
- **Bounties:** for each newly admitted setup, and for reruns on a new engine release.
- **Fees:** for reproductions.
- **Pay per GPU-hour:** for confidential-GPU runs.

Payment follows admission, never submission. Contributors post a stake that a contradicting reproduction slashes. Funding comes from audit revenue.

## Rollout

| Phase | Builds | Done when |
|---|---|---|
| 1 | Roles and keys, public battery, contribution, replay, admission, policy, calibration v2, `contribute`, `verify-contribution`, `calibrate`, `admit` | A first outside setup is admitted by replay, and anyone recomputes a threshold |
| 2 | Large pools, per-question scoring, slices, retirement checks | Pooled slice scores keep honest false alarms at or under 5% |
| 3 | Sealed harness image, attestation checks, key release | One attested confidential-GPU run admitted without replay |
| 4 | Stake, rewards | Six months of admissions with no reversed decision |

## Open questions

- **Public-to-sealed transfer.** How well does a setup's distance on the public battery predict its distance on the sealed one? Measure it on the 52 existing honest runs first.
- **Per-question scoring.** Which normalisation keeps T3 and T4 power when slices change?
- **Policy calls.** Is FP8 KV cache honest for Gemma-4? Is speculative decoding?
- **The review panel.** Who sits on it, and how are conflicts declared?
- **Disputed verdicts.** Should a flagged provider's verdicts pause until its replay finishes?
- **Replay cost.** How many GPU hours can SPOT fund per setup?
