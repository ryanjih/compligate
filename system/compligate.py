#!/usr/bin/env python3
"""Phase 0 MVP 編排器:signals -> CMKB 閘門 -> PR 留言(markdown) + 日誌(jsonl) + 退出碼。
退出碼:gate ∈ fail-on 集合 -> 1(讓 CI check 失敗),否則 0。
日誌每行 = 一次評估,即 in-situ 研究資料集(§7)。"""
import argparse, json, os, sys, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cmkb_reasoner as cg

EMOJI={"merge":"✅","lightweight_verify":"🔎","require_evidence":"📋","full_verify":"🔬",
       "policy_fallback":"♻️","human_escalate":"🙋","block":"⛔"}

def comment_md(pr, sig, r):
    g=r["gate"]
    lines=[f"## {EMOJI.get(g,'•')} CompliGate — gate: **{g.upper()}**  (cost {r['gate_cost']})",
           "",
           f"**Controls touched:** {', '.join(r['controls']) or '—'}  ",
           f"**Regulatory scope:** {', '.join(r['regulatory_scope']) or '—'}",
           "",
           "**Signals**: " + ", ".join(f"`{k}`" for k,v in sig.items() if v) or "**Signals**: (none)",
           "",
           "**Reasoning**:"]
    lines += [f"- {s}" for s in r["reasoning_chain"]]
    if r["evidence_bundle"]:
        lines += ["", "**Required evidence (auto-collected bundle):**"]
        for e in r["evidence_bundle"]:
            lines.append(f"- {', '.join(e['control'])} ({e['for_rule']}): {e['evidence']}")
    resp=r.get("responsibility",{}); units=r.get("units",{})
    if resp:
        lines += ["", "**Responsibility (RACI · ISO 27001 A.5.2/A.5.3):**"]
        for u,d in resp.items():
            label=units.get(u,u)
            seg=[]
            for key,tag in (("responsible_for","R"),("accountable_for","A"),("consulted_on","C"),("informed_of","I")):
                if d.get(key): seg.append(f"{tag}: {', '.join(d[key])}")
            lines.append(f"- **{u}** ({label}): " + " · ".join(seg))
        if r.get("route_to"):
            lines.append(f"- ➡️ **Route this gate to:** {', '.join(r['route_to'])}")
    hb=r.get("handover_brief") or {}
    if hb.get("biz_owns_controls") or hb.get("cloud_resources_to_budget"):
        lines += ["", "**🏛️ 業務/需求單位承接簡報 (handover & budget brief):**"]
        if hb.get("biz_owns_controls"):
            lines.append(f"- 承接後須負責/當責的控制: {', '.join(hb['biz_owns_controls'])}")
        if hb.get("key_risk_rules"):
            lines.append(f"- 須知悉的風險項: {', '.join(hb['key_risk_rules'])}")
        if hb.get("cloud_resources_to_budget"):
            lines.append(f"- ☁️ 須配置並**編列年度經費**的雲端資源: {', '.join(hb['cloud_resources_to_budget'])}")
        if hb.get("budget_action_needed"):
            lines.append("- ⚠️ 本變更涉及可計費雲端資源 — 業務單位須於承接前確認資源與年度經費。")
    lines += ["", "_CompliGate P13 MVP · deterministic & auditable; this comment is the evidence + responsibility + handover record._"]
    return "\n".join(lines)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--signals", help="collect_signals.py 的輸出 JSON 檔(或 stdin)")
    ap.add_argument("--pr", default="local")
    ap.add_argument("--out", default="comment.md")
    ap.add_argument("--log", default="compligate_log.jsonl")
    ap.add_argument("--fail-on", default="block,human_escalate",
                    help="逗號分隔的 gate,命中則退出碼 1")
    a=ap.parse_args()
    raw=json.load(open(a.signals)) if a.signals else json.load(sys.stdin)
    sig=raw.get("signals", raw)
    r=cg.evaluate(sig)
    md=comment_md(a.pr, sig, r)
    open(a.out,"w",encoding="utf-8").write(md+"\n")
    rec={"ts":datetime.datetime.now(datetime.timezone.utc).isoformat(),"pr":a.pr,
         "signals":sig,"gate":r["gate"],"controls":r["controls"],
         "regulatory_scope":r["regulatory_scope"],
         "responsibility":r.get("responsibility",{}),"route_to":r.get("route_to",[]),
         "handover_brief":r.get("handover_brief",{}),
         "evidence_bundle":r["evidence_bundle"],"changed_files":raw.get("changed_files",[])}
    with open(a.log,"a",encoding="utf-8") as fh: fh.write(json.dumps(rec,ensure_ascii=False)+"\n")
    print(md); print(f"\n[compligate] gate={r['gate']}  -> {a.out}, appended {a.log}", file=sys.stderr)
    fail={x.strip() for x in a.fail_on.split(",") if x.strip()}
    sys.exit(1 if r["gate"] in fail else 0)

if __name__=="__main__": main()
