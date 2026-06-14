#!/usr/bin/env python3
"""P13 manuscript figures (English labels). Outputs PNG @200dpi into this dir."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np, os
HERE=os.path.dirname(os.path.abspath(__file__))
def box(ax,x,y,w,h,text="",fc="#eef3fb",ec="#3b6ea5",fs=9,bold=False):
    ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.02,rounding_size=0.05",fc=fc,ec=ec,lw=1.3))
    if text: ax.text(x+w/2,y+h/2,text,ha="center",va="center",fontsize=fs,weight="bold" if bold else "normal")
def arrow(ax,x1,y1,x2,y2,c="#555"):
    ax.add_patch(FancyArrowPatch((x1,y1),(x2,y2),arrowstyle="-|>",mutation_scale=13,lw=1.2,color=c))

# ---------- Fig 1: Architecture ----------
def fig_arch():
    fig,ax=plt.subplots(figsize=(10,7.5)); ax.set_xlim(0,10); ax.set_ylim(0,11); ax.axis("off")
    box(ax,3.6,10.15,2.8,0.65,"Developer push / Pull Request",fc="#fef6e7",ec="#c79a3b",fs=9,bold=True)
    box(ax,3.6,9.2,2.8,0.6,"GitHub Actions trigger",fc="#fef6e7",ec="#c79a3b",fs=9)
    arrow(ax,5,10.15,5,9.82); arrow(ax,5,9.2,5,8.62)
    L=[("L1 Security","gitleaks / semgrep / SCA\nSECRET_RE - CK1 key material","#eef3fb"),
       ("L2 Compliance (C1)","diff/artifact -> CMKB ->\nISO 27001/27701 controls","#e9f5ee"),
       ("L3 Identity/Deploy (C4)","OIDC - RBAC -\ncloud/on-prem DB auth","#f3eefb")]
    bw=2.5; x0=0.9; gap=2.9
    for i,(t,d,c) in enumerate(L):
        x=x0+i*gap
        box(ax,x,6.95,bw,1.45,"",fc=c,ec="#3b6ea5")
        ax.text(x+bw/2,8.08,t,ha="center",va="center",fontsize=8,weight="bold")
        ax.text(x+bw/2,7.42,d,ha="center",va="center",fontsize=7)
        arrow(ax,x+bw/2,6.95,5,6.12)
    box(ax,1.2,5.05,7.6,0.95,"",fc="#e7eefc",ec="#2f5e9e")
    ax.text(5,5.72,"Risk-aware Reasoner (C2)",ha="center",fontsize=9,weight="bold")
    ax.text(5,5.3,"signals -> CMKB rules (forward chaining) -> conjunctive most-strict disposition + axioms",ha="center",fontsize=7.3)
    arrow(ax,5,5.05,5,4.42)
    gates=["merge","lightweight\nverify","require\nevidence","full\nverify","human\nescalate","block"]
    gc=["#dff0df","#eef7df","#fff3cf","#ffe6c7","#ffd9c7","#ffd0d0"]
    for i,(g,c) in enumerate(zip(gates,gc)):
        box(ax,0.45+i*1.6,3.5,1.45,0.82,g,fc=c,ec="#888",fs=7.5)
    ax.text(5,4.55,"gate action  (least -> most strict; conjunctive: most strict wins)",ha="center",fontsize=7.5,style="italic")
    arrow(ax,5,3.5,5,2.9)
    box(ax,0.8,1.7,8.4,1.05,"Per-PR machine-readable Evidence bundle + Reasoning chain\n+ RACI handover & budget brief (C5)",fc="#eef3fb",ec="#3b6ea5",fs=8.5,bold=True)
    arrow(ax,5,1.7,5,1.2)
    box(ax,2.7,0.4,4.6,0.65,"compligate_log.jsonl  (per-PR evidence record)",fc="#f0f0f0",ec="#777",fs=8)
    # title removed; caption provided in manuscript
    fig.savefig(os.path.join(HERE,"fig1_architecture.png"),dpi=200,bbox_inches="tight"); plt.close(fig)

# ---------- Fig 2: CMKB ontology ----------
def fig_cmkb():
    fig,ax=plt.subplots(figsize=(10,7)); ax.set_xlim(0,10.1); ax.set_ylim(0,9); ax.axis("off")
    box(ax,4.0,7.8,2.0,0.75,"CMKB\n(control-mapping KB)",fc="#e7eefc",ec="#2f5e9e",fs=9,bold=True)
    concepts=[("Event /\nArtifact",0.35),("Control\n(ISO 27001/27701)",2.3),("Evidence",4.45),("GateAction",6.45),("Detector",8.45)]
    cw=1.55
    for t,x in concepts:
        box(ax,x,6.0,cw,1.0,t,fc="#eef3fb",ec="#3b6ea5",fs=7.5)
        arrow(ax,5,7.8,x+cw/2,7.05,c="#9bbccc")
    ax.text(5,5.35,"Rule:  trigger (on signals)  ->  controls  ->  evidence  ->  gate",ha="center",fontsize=8.5,weight="bold")
    chain=[("trigger\nsignals.*",0.55),("ISO\ncontrol(s)",2.85),("required\nevidence",5.15),("gate\naction",7.45)]
    cw2=1.7
    for i,(t,x) in enumerate(chain):
        box(ax,x,4.0,cw2,0.9,t,fc="#e9f5ee",ec="#3a8a5a",fs=7.5)
        if i<3: arrow(ax,x+cw2,4.45,chain[i+1][1],4.45,c="#3a8a5a")
    ax.text(9.35,4.45,"axiom may\nupgrade\n(-> block)",ha="left",va="center",fontsize=7,style="italic",color="#a33")
    box(ax,0.35,2.15,4.5,1.05,"",fc="#fff7e6",ec="#c79a3b")
    ax.text(2.6,2.92,"Dimensions",ha="center",fontsize=8,weight="bold")
    ax.text(2.6,2.45,"risk - verifiability -\nauto_detectability - regulatory_scope",ha="center",fontsize=7)
    box(ax,5.15,2.15,4.5,1.05,"",fc="#f3eefb",ec="#7a5ba5")
    ax.text(7.4,2.92,"Ownership (RACI) + Resources  [C5]",ha="center",fontsize=8,weight="bold")
    ax.text(7.4,2.45,"R/A/C/I -> dev/ops/biz -\nannual cloud budget",ha="center",fontsize=7)
    arrow(ax,2.85,4.0,2.6,3.2,c="#c79a3b"); arrow(ax,7.45,4.0,7.4,3.2,c="#7a5ba5")
    ax.text(5,1.45,"Control-mapping knowledge base over PR events and artifacts; extensible: add a rule/detector without changing the reasoner",
            ha="center",fontsize=7.3,style="italic")
    # title removed; caption provided in manuscript
    fig.savefig(os.path.join(HERE,"fig2_cmkb.png"),dpi=200,bbox_inches="tight"); plt.close(fig)

# ---------- Fig 3: Baseline ----------
def fig_baseline():
    det=["gitleaks\n(default)","gitleaks\n(custom)","trufflehog","CK1\n(CompliGate)"]
    P=[1.00,0.86,0.0,1.00]; Rc=[0.46,0.46,0.0,0.69]; F=[0.63,0.60,0.0,0.82]
    x=np.arange(len(det)); w=0.26
    fig,ax=plt.subplots(figsize=(7.8,4.6))
    b1=ax.bar(x-w,P,w,label="precision",color="#2f6e9e")
    b2=ax.bar(x,Rc,w,label="recall",color="#5b8a72")
    b3=ax.bar(x+w,F,w,label="F1",color="#c9a13b")
    for b in (b1,b2,b3):
        for r in b:
            h=r.get_height(); ax.text(r.get_x()+r.get_width()/2,h+0.02,f"{h:.2f}",ha="center",fontsize=7)
    ax.set_xticks(x); ax.set_xticklabels(det,fontsize=8.5); ax.set_ylabel("score"); ax.set_ylim(0,1.14)
    ax.legend(fontsize=8.5,loc="upper left",framealpha=1,ncol=3)
    # title removed; caption provided in manuscript
    fig.savefig(os.path.join(HERE,"fig3_baseline.png"),dpi=200,bbox_inches="tight"); plt.close(fig)

# ---------- Fig 4: Cross-repo ----------
def fig_crossrepo():
    repos=["SchoolSec","rentTeacher","renthouse","tku-mail","checkin"]
    files=[180,72,40,91,17]; pii=[60,51,27,49,11]; seccand=[0,21,4,1,3]; l3=[1,6,1,0,1]; ck1=[4,0,0,0,0]
    x=np.arange(len(repos)); w=0.6
    fig,(axA,axB)=plt.subplots(1,2,figsize=(10.4,4.6))
    # Panel A: PII files (large scale)
    axA.bar(x,pii,w,color="#5b8a72")
    for i,v in enumerate(pii): axA.text(i,v+0.8,str(v),ha="center",fontsize=8,weight="bold")
    for i,f in enumerate(files): axA.text(i,-9,f"{f} files\nBLOCK",ha="center",fontsize=7,weight="bold",color="#b22")
    axA.set_xticks(x); axA.set_xticklabels(repos,fontsize=8,rotation=15)
    axA.set_ylabel("PII files (ISO/IEC 27701)"); axA.set_ylim(0,68)
    axA.set_title("(a) Personal-data processing",fontsize=9,weight="bold")
    # Panel B: security signals (small scale, grouped)
    wb=0.26
    b1=axB.bar(x-wb,seccand,wb,label="secret candidates (regex; incl. FPs)",color="#c9a13b")
    b2=axB.bar(x,l3,wb,label="deployment-locus fails (L3: ID/DB)",color="#7a5ba5")
    b3=axB.bar(x+wb,ck1,wb,label="committed key material (CK1)",color="#2f6e9e")
    for b in (b1,b2,b3):
        for r in b:
            h=r.get_height()
            if h>0: axB.text(r.get_x()+r.get_width()/2,h+0.3,int(h),ha="center",fontsize=7)
    axB.set_xticks(x); axB.set_xticklabels(repos,fontsize=8,rotation=15)
    axB.set_ylabel("count"); axB.set_ylim(0,24)
    axB.set_title("(b) Security signals",fontsize=9,weight="bold")
    axB.legend(fontsize=7.5,loc="upper right",framealpha=1)
    fig.tight_layout()
    fig.savefig(os.path.join(HERE,"fig4_crossrepo.png"),dpi=200,bbox_inches="tight"); plt.close(fig)

for f in (fig_arch,fig_cmkb,fig_baseline,fig_crossrepo): f()
print("done:",sorted(n for n in os.listdir(HERE) if n.endswith(".png")))
