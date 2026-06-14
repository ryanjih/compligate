#!/usr/bin/env python3
"""Controlled GATE evaluation on the synthetic benchmark corpus (real signals -> CMKB reasoner -> action).
Ground truth here = 'a committed secret/credential is present' => should be blocked.
This complements the production per-PR gate evaluation (analyze_gate.py), which awaits report-only data."""
import os,sys,json,re
HB=os.path.dirname(os.path.abspath(__file__)); SYS=os.path.join(HB,"..")
sys.path.insert(0,SYS)
from l3_auth_oracle import check_crypto_keys
from collect_signals import SECRET_RE
import cmkb_reasoner as R
COR=os.path.join(SYS,"nested_secret_benchmark","corpus")
L=json.load(open(os.path.join(SYS,"nested_secret_benchmark","labels.json")))
# Gate ground truth: any committed secret/credential -> should_block.
# = crypto-key positives + the committed generic ApiToken (n07). The other look-alikes are benign.
should_block=set(L["positives"])|{"n07_apitoken.json"}
files=sorted(os.listdir(COR))
rows=[]; tp=fp=fn=tn=0; fns=[]; fps=[]
for f in files:
    c=open(os.path.join(COR,f),encoding="utf-8",errors="ignore").read()
    ck1=bool(check_crypto_keys(f,c) and check_crypto_keys(f,c)[0]["status"]=="fail")
    sec=bool(SECRET_RE.search(c))
    sig={"crypto_key_in_diff":ck1,"secret_in_diff":sec}
    gate=R.evaluate(sig)["gate"]
    pred_block=(gate=="block"); gt=(f in should_block)
    if pred_block and gt: tp+=1
    elif pred_block and not gt: fp+=1; fps.append(f)
    elif (not pred_block) and gt: fn+=1; fns.append(f)
    else: tn+=1
    rows.append((f,ck1,sec,gate,gt))
P=tp/(tp+fp) if tp+fp else 0; Rc=tp/(tp+fn) if tp+fn else 0; F=2*P*Rc/(P+Rc) if P+Rc else 0
ob=fp/(fp+tn) if fp+tn else 0
print("=== Controlled GATE evaluation on benchmark (24 files; gt = committed secret present) ===")
print(f"should-block={len(should_block)}  should-allow={24-len(should_block)}")
print(f"TP={tp} FP={fp} FN={fn} TN={tn} | precision={P:.3f} recall={Rc:.3f} F1={F:.3f} | over-blocking rate={ob:.3f}")
print(f"gate false-negatives (missed secrets): {fns}")
print(f"gate false-positives (over-blocked benign): {fps}")
json.dump(dict(TP=tp,FP=fp,FN=fn,TN=tn,precision=round(P,3),recall=round(Rc,3),F1=round(F,3),
               over_blocking_rate=round(ob,3),false_negatives=fns,false_positives=fps),
          open(os.path.join(HB,"gate_benchmark_results.json"),"w"),indent=2)
