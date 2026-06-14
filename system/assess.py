#!/usr/bin/env python3
"""上線前合規與承接體檢(唯讀)。對整個 repo 現況跑 CompliGate 檢核 ->
go-live 就緒報告 + 校安/學務業務單位承接與經費簡報。
唯讀:不寫入目標 repo;secret 只記檔名與規則、不印值;data 檔(csv/sql/xlsx)只記存在、不讀內容。
用法: python3 assess.py --repo /path/to/clone [--llm] --out report.md
"""
import argparse, json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collect_signals as cs, l3_auth_oracle as l3, cmkb_reasoner as cg

import re as _re
BIN_EXT=(".map",".ttf",".woff",".woff2",".eot",".png",".ico",".jpg",".jpeg",".gif",".pdf",".dll",".exe")
DATA_EXT=(".csv",".sql",".xlsx",".xls",".db",".sqlite",".bak",".mdf")
VENDOR=_re.compile(r'(wwwroot/lib/|\.min\.(js|css)$|\.bundle\.js$|node_modules/|/dist/)', _re.I)  # 第三方函式庫,排除內容掃描

def tracked(repo):
    out=subprocess.check_output(["git","-C",repo,"ls-files"],text=True)
    return [l.strip() for l in out.splitlines() if l.strip()]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--repo",required=True)
    ap.add_argument("--llm",action="store_true")
    ap.add_argument("--out",default="prelaunch_assessment.md")
    ap.add_argument("--c4",default="deployment_locus_dataset.jsonl")
    a=ap.parse_args()
    files=tracked(a.repo)
    data_files=[f for f in files if f.lower().endswith(DATA_EXT)]
    code_files=[f for f in files if not f.lower().endswith(BIN_EXT+DATA_EXT)]

    secret_hits=[]; l3_checks=[]; pii_files=set()
    for f in code_files:
        if VENDOR.search(f): continue                               # 跳過第三方函式庫(避免誤報)
        p=os.path.join(a.repo,f)
        try:
            if os.path.getsize(p)>300_000: continue
            c=open(p,encoding="utf-8",errors="ignore").read()
        except Exception: continue
        if cs.SECRET_RE.search(c): secret_hits.append(f)            # 只記檔名
        if cs.PII_PAT.search(f) or cs.PII_PAT.search(c): pii_files.add(f)
        l3_checks += [{**x,"file":f} for x in l3.check_identity(f,c)]
        l3_checks += [{**x,"file":f} for x in l3.check_db(f,c)]
        l3_checks += [{**x,"file":f} for x in l3.check_crypto_keys(f,c)]

    sast = cs.semgrep_high([os.path.join(a.repo,f) for f in code_files if f.endswith((".cs",".js",".py",".ts"))])
    id_fail=any(x["status"]=="fail" and x["control"] in ("A.5.15","A.5.16","A.8.2") for x in l3_checks)
    db_fail=any(x["status"]=="fail" and x["check"] in ("DB1_no_plaintext_cred","DB2_tls_enforced") for x in l3_checks)
    crypto_fail=any(x["status"]=="fail" and x["check"]=="CK1_no_committed_crypto_key" for x in l3_checks)
    blob=" ".join(code_files)
    signals={
      "secret_in_diff": bool(secret_hits),
      "crypto_key_in_diff": crypto_fail,
      "sast_high": bool(sast) if sast is not None else False,
      "pii_flow": bool(pii_files),
      "identity_change": any(x["control"].startswith("A.5") or x["control"]=="A.8.2" for x in l3_checks),
      "db_conn_change": any(x["check"] in ("DB1_no_plaintext_cred","DB2_tls_enforced") for x in l3_checks),
      "identity_auth_fail": id_fail, "db_auth_fail": db_fail,
      "cloud_resource_provision": any(cs.IAC_FILE.search(f) for f in code_files),
      "identity_data_import": any(cs.IMPORT_PAT.search(f) for f in code_files) or bool(data_files),
      "access_logging_change": any(cs.LOG_PAT.search(f) for f in code_files),
    }
    # AIDF:選用 LLM 複審測試檔(上限 8)
    aidf_findings=[]
    if a.llm:
        tests=[f for f in code_files if "/test" in f.lower() or f.lower().startswith("tests/") or "_test" in f.lower() or ".tests" in f.lower()]
        for tf in tests[:8]:
            try:
                tcode=open(os.path.join(a.repo,tf),encoding="utf-8",errors="ignore").read()
                comp,reason=l3 and __import__("aidf_bridge").llm_review(tcode,"")
                if comp: signals["complicit_oracle"]=True; aidf_findings.append({"file":tf,"reason":reason})
            except Exception as e: aidf_findings.append({"file":tf,"error":str(e)[:80]})

    r=cg.evaluate(signals)
    # C4 dataset
    import datetime
    with open(a.c4,"a",encoding="utf-8") as fh:
        for x in l3_checks:
            fh.write(json.dumps({"ts":datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "repo":os.path.basename(a.repo.rstrip("/")),"locus":"deployment","check":x["check"],
                "file":x["file"],"control":x["control"],"gt_failure":1 if x["status"]=="fail" else 0},ensure_ascii=False)+"\n")

    L=[]
    L.append(f"# 上線前合規與承接體檢 — {os.path.basename(a.repo.rstrip('/'))}")
    L.append(f"\n_唯讀掃描 {len(code_files)} 個程式/設定檔;data 檔 {len(data_files)} 個僅記存在未讀內容。HEAD: "
             f"{subprocess.check_output(['git','-C',a.repo,'log','--oneline','-1'],text=True).strip()}_\n")
    L.append(f"## 整體閘門裁決:**{r['gate'].upper()}**  (cost {r['gate_cost']})")
    L.append(f"- 觸發控制: {', '.join(r['controls']) or '—'}")
    L.append(f"- 法規範圍: {', '.join(r['regulatory_scope']) or '—'}")
    fails=[x for x in l3_checks if x["status"]=="fail"]
    L.append(f"\n## 🔴 上線前須處理 (L3 認證 oracle FAIL: {len(fails)})")
    if fails:
        for x in fails:
            det=f" 〔{x['detail']}〕" if x.get('detail') else ""
            L.append(f"- **{x['check']}** ({x['control']}) — `{x['file']}`：{x['req']}{det}")
    else: L.append("- (無 L3 認證失敗)")
    L.append(f"\n## 其他發現")
    L.append(f"- secret 疑慮檔: {', '.join(f'`{x}`' for x in secret_hits) or '無'}（僅列檔名,請人工確認/輪替）")
    L.append(f"- SAST high: {'是(semgrep)' if signals['sast_high'] else ('否' if sast is not None else '未掃(semgrep 缺席)')}")
    L.append(f"- 個資處理檔: {len(pii_files)} 個（→ ISO 27701 PIMS 證據需求）")
    L.append(f"- 存取紀錄/稽核設定: {'偵測到' if signals['access_logging_change'] else '⚠️ 未偵測到 — 上線前確認 A.8.15 logging'}")
    L.append(f"- 雲端資源(IaC/部署): {'有' if signals['cloud_resource_provision'] else '未在 repo 內(部署於外部設定?)'}")
    if aidf_findings:
        L.append(f"- AIDF 測試共謀複審: " + ("; ".join(f"`{x.get('file')}`" for x in aidf_findings if x.get('reason')) or "未發現共謀"))
    # 承接簡報
    hb=r.get("handover_brief") or {}
    L.append(f"\n## 🏛️ 校安/學務業務單位 承接與經費簡報")
    L.append(f"- 承接後當責控制: {', '.join(hb.get('biz_owns_controls',[])) or '—'}")
    L.append(f"- 須知悉風險項: {', '.join(hb.get('key_risk_rules',[])) or '—'}")
    L.append(f"- ☁️ 須配置/編列年度經費的雲端資源: {', '.join(hb.get('cloud_resources_to_budget',[])) or '—'}")
    # RACI
    L.append(f"\n## 責任歸屬 (RACI · A.5.2/A.5.3)")
    for u,d in (r.get("responsibility") or {}).items():
        seg=[f"{t}: {', '.join(d[k])}" for k,t in (("responsible_for","R"),("accountable_for","A"),("consulted_on","C"),("informed_of","I")) if d.get(k)]
        L.append(f"- **{u}** ({r['units'].get(u,u)}): " + " · ".join(seg))
    open(a.out,"w",encoding="utf-8").write("\n".join(L)+"\n")
    print("\n".join(L))
    print(f"\n[assess] -> {a.out}", file=sys.stderr)

if __name__=="__main__": main()
