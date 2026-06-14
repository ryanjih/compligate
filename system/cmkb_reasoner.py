#!/usr/bin/env python3
"""P13 CMKB 推論器 (C2):由 PR signals -> CMKB 規則/控制 -> 合取式把關 + 自動證據束 + 理由鏈。
合取語意:PR 必須滿足所有被觸發控制,故 PR 閘門 = 所有 fired 規則所需動作中『最嚴(strength 最大)』者。
公理(cmkb.axioms)可升級個別規則的所需動作。沿用 P12 的「失效驅動決策」精神,擴成合規多動作。"""
import sys, json
from pathlib import Path
import yaml

CMKB = yaml.safe_load((Path(__file__).with_name("cmkb.yaml")).read_text())
GA = {g["id"]: g for g in CMKB["gate_actions"]}
def strength(a): return GA[a]["strength"]

def _match(cond, signals):
    """評估規則 cond(僅限 'signals.X == true/false' 以 and 連接)。未知 signal 預設 False。"""
    expr = cond.replace("signals.", "")
    ns = {"true": True, "false": False}
    # 收集 cond 內提到的識別字,缺者補 False
    import re
    for name in set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr)):
        if name in ("and","or","not","true","false","in"): continue
        ns.setdefault(name, signals.get(name, False))
    try:
        return bool(eval(expr, {"__builtins__": {}}, ns))
    except Exception:
        return False

def _axiom_required(ax, rule_id, scope):
    """若公理適用於此規則,回傳其 require / require_min 動作,否則 None。"""
    when = ax.get("when", "")
    applies = False
    if "rule ==" in when:
        applies = rule_id == when.split("rule ==")[1].strip()
    elif "rule in [" in when:
        ids = when.split("[")[1].split("]")[0].replace(" ", "").split(",")
        applies = rule_id in ids
    elif "regulatory_scope in [" in when:
        scopes = when.split("[")[1].split("]")[0].replace(" ", "").split(",")
        applies = scope in scopes
    if not applies: return None, None
    return ax.get("require"), ax.get("require_min")

def evaluate(signals):
    """回傳 PR 層級把關決策 dict。"""
    fired = []
    for r in CMKB["rules"]:
        if not _match(r["cond"], signals): continue
        required = r["gate"]; applied_ax = []
        scope = r.get("dims", {}).get("regulatory_scope", "none")
        for ax in CMKB.get("axioms", []):
            req, req_min = _axiom_required(ax, r["id"], scope)
            if req and strength(req) > strength(required):
                required = req; applied_ax.append(ax["id"])
            elif req_min and strength(req_min) > strength(required):
                required = req_min; applied_ax.append(ax["id"])
        fired.append(dict(rule=r["id"], controls=r["controls"], evidence=r["evidence"],
                          required=required, scope=scope, axioms=applied_ax))
    if not fired:
        return dict(gate="merge", gate_cost=GA["merge"]["cost"], controls=[], evidence_bundle=[],
                    regulatory_scope=[], reasoning_chain=["no control triggered -> merge"],
                    responsibility={}, route_to=[], handover_brief={}, units=CMKB.get("units",{}), fired=[])
    # 合取:取最嚴
    gate = max((f["required"] for f in fired), key=strength)
    controls = sorted({c for f in fired for c in f["controls"]})
    scopes = sorted({f["scope"] for f in fired if f["scope"] != "none"})
    evidence = [{"control": f["controls"], "evidence": f["evidence"], "for_rule": f["rule"]}
                for f in fired]
    chain = []
    for f in fired:
        ax = (" + axioms " + ",".join(f["axioms"])) if f["axioms"] else ""
        chain.append(f"[{f['rule']}] -> {f['controls']} -> {f['required']}{ax}")
    chain.append(f"conjunctive gate = max-strength({[f['required'] for f in fired]}) -> {gate}")
    # 責任歸屬(RACI:R/A/C/I):ISO 27001 A.5.2/A.5.3
    own = CMKB.get("ownership", {}); resmap = CMKB.get("resources", {})
    resp = {}
    for f in fired:
        o = own.get(f["rule"], {})
        for role in ("R","A","C","I"):
            u=o.get(role)
            if u: resp.setdefault(u,{k:set() for k in "RACI"})[role].update(f["controls"])
    RK={"R":"responsible_for","A":"accountable_for","C":"consulted_on","I":"informed_of"}
    responsibility={u:{RK[k]:sorted(v[k]) for k in "RACI" if v[k]} for u,v in resp.items()}
    gate_rules=[f for f in fired if f["required"]==gate]
    route_to=sorted({own.get(f["rule"],{}).get("R") for f in gate_rules if own.get(f["rule"],{}).get("R")})
    for f in fired: f["owner"]=own.get(f["rule"],{})
    # 業務單位(biz)承接簡報:其責任 + 風險 + 須編列經費的雲端資源
    biz_owns=sorted({c for f in fired for k in ("R","A") if own.get(f["rule"],{}).get(k)=="biz" for c in f["controls"]})
    risks=sorted({f["rule"] for f in fired if f.get("required") in ("block","human_escalate","full_verify")})
    cloud_res=sorted({resmap[f["rule"]] for f in fired if f["rule"] in resmap})
    handover_brief={"biz_owns_controls":biz_owns,"key_risk_rules":risks,
                    "cloud_resources_to_budget":cloud_res,"budget_action_needed":bool(cloud_res)}
    return dict(gate=gate, gate_cost=GA[gate]["cost"], controls=controls,
                regulatory_scope=scopes, evidence_bundle=evidence, reasoning_chain=chain,
                responsibility=responsibility, route_to=route_to, handover_brief=handover_brief,
                units=CMKB.get("units",{}), fired=fired)

if __name__ == "__main__":
    samples = {
      "clean PR": {"new_dependency": False},
      "AI test + new dep": {"complicit_oracle": True, "new_dependency": True},
      "secret leak": {"secret_in_diff": True},
      "identity + PII change": {"identity_change": True, "pii_flow": True},
      "DB conn + high CVE": {"db_conn_change": True, "new_dependency": True, "high_cve": True},
    }
    for name, sig in samples.items():
        r = evaluate(sig)
        print(f"\n### {name}  ->  GATE = {r['gate'].upper()}  (cost {r['gate_cost']})")
        print("  controls:", r["controls"], " | reg:", r["regulatory_scope"])
        for step in r["reasoning_chain"]: print("   ", step)
        if r["evidence_bundle"]:
            print("  evidence bundle:")
            for e in r["evidence_bundle"]: print(f"    - {e['for_rule']} {e['control']}: {e['evidence'][:70]}")
