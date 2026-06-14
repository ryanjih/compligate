# Gate evaluation — per-PR ground-truth annotation protocol (T13)

Goal: turn report-only / enforce-mode operation into a confusion-matrix evaluation of the
**gate disposition**, addressing the reviewer's request for true/false positives & negatives,
over-blocking rate, escalation rate, post-fix downgrade, action distribution, and latency.

This is **artifact/log analysis of the author's own repositories** (no human subjects, IRB-free).
Raw logs stay private; only anonymised aggregate results are released.

## Inputs
1. `compligate_log.jsonl` — one JSON object per PR produced by CompliGate (predicted side):
   `{ "pr_id": "...", "repo": "...", "phase": "pre|post-fix", "gate": "<action>",
      "disposition": ["<action>", ...], "controls": [...], "latency_ms": <int>,
      "remediated": 0|1 }`
2. `ground_truth.csv` — one row per PR (human label), columns:
   `pr_id, gt_should_block, gt_action, remediated, notes`
   - `gt_should_block` ∈ {0,1}: does this PR contain a real, merge-worthy-blocking deficiency?
   - `gt_action` ∈ ACTIONS (the action a careful reviewer would require).
   - `remediated` ∈ {0,1}: was the finding fixed and the PR re-run (`phase=post-fix`)?

## Labeling rules (to reduce circularity — reviewer point 9)
- The labeler assigns `gt_should_block` / `gt_action` **from the diff and evidence only**,
  WITHOUT consulting CompliGate's gate output for that PR.
- Where feasible, a second independent labeler annotates a sample; report inter-rater
  agreement (Cohen's κ). Resolve disagreements before computing metrics.
- A "secret/credential present and committed" is should_block; an `.env.example` placeholder
  or KeyVault reference is not.

## ACTION ordinal scale (least → most strict)
merge < lightweight_verify < require_evidence < full_verify < human_escalate < block

## Metrics produced by `analyze_gate.py`
- Block-level confusion matrix (predicted block vs gt_should_block): TP/FP/FN/TN, precision, recall.
- **Over-blocking rate** = FP / (FP + TN)  (blocked among PRs that should have been allowed).
- **Escalation rate** = #(gate == human_escalate) / N.
- **Post-fix downgrade** = among remediated PRs blocked pre-fix, fraction whose post-fix gate == merge.
- **Action confusion matrix** (predicted gate action × gt_action) — full distribution, not just BLOCK.
- **Latency**: mean / median / p95 of `latency_ms`.

## Usage
    python3 analyze_gate.py --log compligate_log.jsonl --truth ground_truth.csv
    python3 analyze_gate.py --demo      # runs on a small synthetic example (format illustration)
