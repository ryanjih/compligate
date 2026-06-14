#!/usr/bin/env python3
"""Benchmark v2 harness: detection P/R/F1 (+bootstrap CI) for gitleaks default/custom, trufflehog, CK1;
CK1 ablation (4 variants); controlled gate confusion matrix; runtime. Reports on held-out TEST split."""
import os,sys,json,re,subprocess,tempfile,time,random
HERE=os.path.dirname(os.path.abspath(__file__)); COR=os.path.join(HERE,"corpus"); SYS=os.path.join(HERE,"..")
sys.path.insert(0,SYS)
from l3_auth_oracle import check_crypto_keys, _is_key_material, RE_CRYPTO_NAME
import cmkb_reasoner as R
try: from collect_signals import SECRET_RE
except Exception: SECRET_RE=re.compile(r'(?i)(api[_-]?key|secret|password|bearer|token)\s*[:=]')
meta=json.load(open(os.path.join(HERE,"labels.json")))
files=sorted(meta)
content={f:open(os.path.join(COR,f),encoding="utf-8",errors="ignore").read() for f in files}
cls={f:meta[f]["class"] for f in files}; split={f:meta[f]["split"] for f in files}
TEST=[f for f in files if split[f]=="test"]
# detection task: positive=crypto_pos ; negative=crypto_lookalike_neg + benign_other ; exclude generic_secret
DET=[f for f in TEST if cls[f] in ("crypto_pos","crypto_lookalike_neg","benign_other")]
POS=set(f for f in DET if cls[f]=="crypto_pos")

def prf(hit,universe,pos):
    hit=set(hit)&set(universe); pos=set(pos)&set(universe); neg=set(universe)-pos
    tp=len(hit&pos); fp=len(hit&neg); fn=len(pos-hit); tn=len(neg-hit)
    P=tp/(tp+fp) if tp+fp else 0.0; Rc=tp/(tp+fn) if tp+fn else 0.0; F=2*P*Rc/(P+Rc) if P+Rc else 0.0
    return tp,fp,fn,tn,P,Rc,F
def boot(hit,universe,pos,B=2000):
    rng=random.Random(7); U=list(universe); Ps=set(pos); H=set(hit); Fs=[]
    for _ in range(B):
        s=[U[rng.randrange(len(U))] for _ in U]
        tp=sum(1 for x in s if x in H and x in Ps); fp=sum(1 for x in s if x in H and x not in Ps)
        fn=sum(1 for x in s if x not in H and x in Ps)
        P=tp/(tp+fp) if tp+fp else 0; Rc=tp/(tp+fn) if tp+fn else 0
        Fs.append(2*P*Rc/(P+Rc) if P+Rc else 0)
    Fs.sort(); lo=Fs[int(0.025*B)]; hi=Fs[int(0.975*B)-1]; return round(lo,2),round(hi,2)

def gitleaks(cfg=None):
    out=os.path.join(tempfile.gettempdir(),"gl.json")
    cmd=["gitleaks","dir",COR,"--report-format","json","--report-path",out,"--no-banner","--exit-code","0"]
    if cfg: cmd+=["-c",cfg]
    subprocess.run(cmd,capture_output=True,text=True)
    try: d=json.load(open(out))
    except: d=[]
    return {os.path.basename(x.get("File","")) for x in d}
def truffle():
    r=subprocess.run(["trufflehog","filesystem",COR,"--json","--no-update","--no-verification"],capture_output=True,text=True)
    h=set()
    for ln in r.stdout.splitlines():
        try:
            d=json.loads(ln); fp=d.get("SourceMetadata",{}).get("Data",{}).get("Filesystem",{}).get("file","")
            if fp: h.add(os.path.basename(fp))
        except: pass
    return h
def ck1(): return {f for f in files if (lambda r: r and r[0]["status"]=="fail")(check_crypto_keys(f,content[f]))}

ALLOW=re.compile(r'@Microsoft\.KeyVault|\$\{|#\{|\{\{|example|changeme|your-key|secret://',re.I)
def variant(name_ctx,entropy,allow):
    hit=set()
    for f in files:
        c=content[f]; found=False
        def consider(val,under):
            s=str(val)
            if allow and ALLOW.search(s): return False
            nm = under if name_ctx else True
            en = _is_key_material(s) if entropy else (isinstance(val,str) and len(s.strip(' "\''))>=6 and val not in (None,""))
            return nm and en
        try:
            obj=json.loads(c)
            def walk(o,u):
                nonlocal found
                if isinstance(o,dict):
                    for k,v in o.items(): walk(v, u or bool(RE_CRYPTO_NAME.search(str(k))))
                elif isinstance(o,list):
                    for v in o: walk(v,u)
                else:
                    if consider(o,u): found=True
            walk(obj,False)
        except Exception:
            for ln in c.splitlines():
                m=re.match(r'\s*//',ln) ; 
                if m: continue
                mm=re.match(r'[^\w]*([\w.\-]+)\s*[:=]\s*["\']?([^"\'\n]+)',ln)
                if mm and consider(mm.group(2), bool(RE_CRYPTO_NAME.search(mm.group(1)))): found=True
        if found: hit.add(f)
    return hit

print(f"=== Detection task on HELD-OUT TEST ({len(DET)} files: {len(POS)} crypto positives, {len(DET)-len(POS)} negatives) ===")
tools={"gitleaks (default)":gitleaks(),"gitleaks (custom rule)":gitleaks(os.path.join(HERE,"gitleaks_crypto.toml")),
       "trufflehog":truffle(),"CK1 (CompliGate)":ck1()}
hdr=f"{'detector':24}{'TP':>3}{'FP':>3}{'FN':>3}{'TN':>3}{'prec':>7}{'rec':>7}{'F1':>7}  F1 95% CI"
print(hdr); print("-"*len(hdr))
det_res={}
for k,h in tools.items():
    tp,fp,fn,tn,P,Rc,F=prf(h,DET,POS); lo,hi=boot(h,DET,POS)
    det_res[k]=dict(TP=tp,FP=fp,FN=fn,TN=tn,precision=round(P,2),recall=round(Rc,2),F1=round(F,2),F1_CI=[lo,hi])
    print(f"{k:24}{tp:>3}{fp:>3}{fn:>3}{tn:>3}{P:>7.2f}{Rc:>7.2f}{F:>7.2f}  [{lo},{hi}]")

print(f"\n=== CK1 ablation on HELD-OUT TEST ===")
abl={"entropy only":variant(False,True,False),"key-name context only":variant(True,False,False),
     "context + entropy":variant(True,True,False),"context + entropy + allowlist":variant(True,True,True)}
abl_res={}
for k,h in abl.items():
    tp,fp,fn,tn,P,Rc,F=prf(h,DET,POS); abl_res[k]=dict(precision=round(P,2),recall=round(Rc,2),F1=round(F,2))
    print(f"{k:30} P={P:.2f} R={Rc:.2f} F1={F:.2f}")

# gate eval (full corpus): should_block = crypto_pos + generic_secret
sb=set(f for f in files if cls[f] in ("crypto_pos","generic_secret"))
ck1h=ck1(); tp=fp=fn=tn=0; gfp=[]; gfn=[]
for f in files:
    sig={"crypto_key_in_diff": f in ck1h, "secret_in_diff": bool(SECRET_RE.search(content[f]))}
    g=R.evaluate(sig)["gate"]; pb=(g=="block"); gt=(f in sb)
    if pb and gt: tp+=1
    elif pb and not gt: fp+=1; gfp.append(f)
    elif not pb and gt: fn+=1; gfn.append(f)
    else: tn+=1
P=tp/(tp+fp) if tp+fp else 0; Rc=tp/(tp+fn) if tp+fn else 0; ob=fp/(fp+tn) if fp+tn else 0
print(f"\n=== Controlled GATE eval (full corpus {len(files)} files; should-block={len(sb)}) ===")
print(f"TP={tp} FP={fp} FN={fn} TN={tn} | precision={P:.2f} recall={Rc:.2f} over-blocking={ob:.2f}")
print(f"  gate FP (over-block): {gfp}\n  gate FN (missed): {gfn[:6]}{'...' if len(gfn)>6 else ''}")

# runtime
t=time.perf_counter()
for f in files: check_crypto_keys(f,content[f])
ck1_ms=(time.perf_counter()-t)*1000
t=time.perf_counter(); gitleaks(); gl_ms=(time.perf_counter()-t)*1000
print(f"\n=== Runtime ({len(files)} files) === CK1: {ck1_ms:.1f} ms total ({ck1_ms/len(files):.2f} ms/file) | gitleaks dir: {gl_ms:.0f} ms")
json.dump(dict(detection=det_res,ablation=abl_res,
               gate=dict(TP=tp,FP=fp,FN=fn,TN=tn,precision=round(P,2),recall=round(Rc,2),over_blocking=round(ob,2),fp=gfp,fn=gfn),
               runtime=dict(ck1_ms_total=round(ck1_ms,1),ck1_ms_per_file=round(ck1_ms/len(files),2),gitleaks_ms=round(gl_ms)),
               counts=dict(files=len(files),det_test=len(DET),det_pos=len(POS),should_block=len(sb))),
          open(os.path.join(HERE,"results.json"),"w"),indent=2)
print("\nwrote results.json")
