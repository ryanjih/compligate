#!/usr/bin/env python3
"""Gate-disposition confusion-matrix evaluation (scaffold for T13).
Computes block-level & action-level confusion matrices, over-blocking/escalation rates,
post-fix downgrade, and latency stats from CompliGate logs + human ground truth.
Run with --demo to see the format on synthetic data; replace with real inputs when available."""
import argparse, json, csv, statistics, sys
ACTIONS=["merge","lightweight_verify","require_evidence","full_verify","human_escalate","block"]
BLOCKISH={"block"}  # predicted "should block" set; adjust if enforce blocks on >=human_escalate

def load_log(p):
    return [json.loads(l) for l in open(p,encoding="utf-8") if l.strip()]
def load_truth(p):
    return list(csv.DictReader(open(p,encoding="utf-8")))

def evaluate(log, truth):
    gt={r["pr_id"]:r for r in truth}
    rows=[r for r in log if r.get("pr_id") in gt and r.get("phase","pre")!="post-fix"]
    # block-level
    tp=fp=fn=tn=0
    for r in rows:
        pred=1 if r.get("gate") in BLOCKISH else 0
        g=int(gt[r["pr_id"]]["gt_should_block"])
        tp+=pred==1 and g==1; fp+=pred==1 and g==0; fn+=pred==0 and g==1; tn+=pred==0 and g==0
    P=tp/(tp+fp) if tp+fp else 0.0; R=tp/(tp+fn) if tp+fn else 0.0
    F=2*P*R/(P+R) if P+R else 0.0
    overblock=fp/(fp+tn) if fp+tn else 0.0
    esc=sum(1 for r in rows if r.get("gate")=="human_escalate")/len(rows) if rows else 0.0
    # post-fix downgrade
    pre={r["pr_id"]:r for r in log if r.get("phase","pre")!="post-fix"}
    post={r["pr_id"]:r for r in log if r.get("phase")=="post-fix"}
    rem=[pid for pid in post if pre.get(pid,{}).get("gate") in BLOCKISH and int(gt.get(pid,{}).get("remediated",0))]
    downgraded=sum(1 for pid in rem if post[pid].get("gate")=="merge")
    # action confusion matrix
    idx={a:i for i,a in enumerate(ACTIONS)}
    M=[[0]*len(ACTIONS) for _ in ACTIONS]
    for r in rows:
        ga=gt[r["pr_id"]].get("gt_action"); pa=r.get("gate")
        if ga in idx and pa in idx: M[idx[ga]][idx[pa]]+=1
    lat=[r["latency_ms"] for r in rows if isinstance(r.get("latency_ms"),(int,float))]
    return dict(N=len(rows),TP=tp,FP=fp,FN=fn,TN=tn,precision=round(P,3),recall=round(R,3),F1=round(F,3),
                over_blocking_rate=round(overblock,3),escalation_rate=round(esc,3),
                post_fix_downgrade=f"{downgraded}/{len(rem)}" if rem else "n/a",
                action_matrix=M,
                latency_ms=(dict(mean=round(statistics.mean(lat),1),median=statistics.median(lat),
                                 p95=sorted(lat)[max(0,int(0.95*len(lat))-1)]) if lat else None))

def show(res):
    print(f"PRs evaluated (pre-fix): {res['N']}")
    print(f"Block-level: TP={res['TP']} FP={res['FP']} FN={res['FN']} TN={res['TN']} | "
          f"P={res['precision']} R={res['recall']} F1={res['F1']}")
    print(f"Over-blocking rate: {res['over_blocking_rate']} | Escalation rate: {res['escalation_rate']} | "
          f"Post-fix downgrade to merge: {res['post_fix_downgrade']}")
    print(f"Latency (ms): {res['latency_ms']}")
    print("\nAction confusion matrix (rows=ground truth, cols=predicted gate):")
    w=max(len(a) for a in ACTIONS)
    print(" "*(w+2)+" ".join(f"{a[:6]:>6}" for a in ACTIONS))
    for i,a in enumerate(ACTIONS):
        print(f"{a:>{w}}  "+" ".join(f"{res['action_matrix'][i][j]:>6}" for j in range(len(ACTIONS))))

def demo():
    log=[
      {"pr_id":"PR1","phase":"pre","gate":"block","latency_ms":120},
      {"pr_id":"PR2","phase":"pre","gate":"merge","latency_ms":80},
      {"pr_id":"PR3","phase":"pre","gate":"block","latency_ms":140},
      {"pr_id":"PR4","phase":"pre","gate":"human_escalate","latency_ms":110},
      {"pr_id":"PR5","phase":"pre","gate":"require_evidence","latency_ms":90},
      {"pr_id":"PR1","phase":"post-fix","gate":"merge","latency_ms":75},
    ]
    truth=[
      {"pr_id":"PR1","gt_should_block":"1","gt_action":"block","remediated":"1"},
      {"pr_id":"PR2","gt_should_block":"0","gt_action":"merge","remediated":"0"},
      {"pr_id":"PR3","gt_should_block":"1","gt_action":"block","remediated":"0"},
      {"pr_id":"PR4","gt_should_block":"1","gt_action":"human_escalate","remediated":"0"},
      {"pr_id":"PR5","gt_should_block":"0","gt_action":"require_evidence","remediated":"0"},
    ]
    print("=== DEMO (synthetic; illustrates output format only) ===")
    show(evaluate(log,truth))

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--log"); ap.add_argument("--truth"); ap.add_argument("--demo",action="store_true")
    ap.add_argument("--out",default="gate_eval_results.json")
    a=ap.parse_args()
    if a.demo or not (a.log and a.truth): 
        if not a.demo: print("(no --log/--truth given; showing --demo)\n",file=sys.stderr)
        demo(); sys.exit(0)
    res=evaluate(load_log(a.log),load_truth(a.truth)); show(res)
    json.dump(res,open(a.out,"w"),indent=2); print(f"\nwrote {a.out}")
