# CompliGate

Artifacts for the paper **"CompliGate: Context-Aware Secret Detection and Control-Mapped Security Gating in CI/CD"** (Chen-Chung Chi, Tamkang University).

CompliGate is a knowledge-based, risk-aware gate that runs at each pull request: a **Control-Mapping Knowledge Base (CMKB)** maps events and artifacts to ISO/IEC 27001:2022 and 27701:2025-aligned controls, required evidence, and graded gate actions; a deterministic reasoner aggregates the triggered controls into an auditable disposition.

**Scope.** This is a secret-management and control-assurance tool. It detects committed secrets and credentials (including cryptographic key material) and **does not design or analyse cryptographic algorithms or protocols**. The reasoner is deterministic and **uses no machine learning**; verification of AI-generated code or tests is out of scope and not included here.

## Contents
- `system/cmkb.yaml` — the Control-Mapping Knowledge Base (rules, controls, evidence, gate actions, axioms).
- `system/cmkb_reasoner.py` — the deterministic risk-aware reasoner (`evaluate(signals)`).
- `system/l3_auth_oracle.py` — context-aware detector incl. **CK1** committed-key detection.
- `system/collect_signals.py`, `system/compligate.py`, `system/assess.py` — signal collection and the gate entry points.
- `system/nested_secret_benchmark/` — released synthetic benchmark (`gen_benchmark.py`, `run_benchmark.py`, `corpus/`, `labels.json`, `results.json`, custom gitleaks rule).
- `system/gate_eval/` — gate confusion-matrix protocol and scripts (`annotation_protocol.md`, `analyze_gate.py`, `run_gate_on_benchmark.py`).
- `system/sample_evidence_bundle.json` — example per-PR evidence record.
- `figures/make_figures.py` — figure generation.
- `.github/workflows/compligate.yml` — example CI workflow.

## Reproduce the evaluation
Requirements: Python 3.9+, [gitleaks](https://github.com/gitleaks/gitleaks) 8.30+, [trufflehog](https://github.com/trufflesecurity/trufflehog) 3.95+, `pyyaml`, `matplotlib`.
```bash
python3 system/nested_secret_benchmark/gen_benchmark.py     # regenerate the synthetic corpus
python3 system/nested_secret_benchmark/run_benchmark.py     # detection P/R/F1 (+CI), ablation, gate, runtime
python3 system/gate_eval/run_gate_on_benchmark.py           # controlled gate confusion matrix
python3 system/gate_eval/analyze_gate.py --demo             # gate-evaluation scaffold (format demo)
```

## Data availability
The synthetic benchmark is fully included. The in-situ assessment logs derive from the author's own production repositories and contain sensitive personal data; raw logs are **not** included. Only anonymised aggregate results appear in the paper.

## License
MIT (see `LICENSE`).

## Citation
Chen-Chung Chi. *CompliGate: Context-Aware Secret Detection and Control-Mapped Security Gating in CI/CD.* (under review).
