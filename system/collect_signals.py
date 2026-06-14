#!/usr/bin/env python3
"""Phase 0 MVP — 收集 PR signals(啟發式 + 可選掃描器)。
輸出 signals JSON 給 cmkb_reasoner。掃描器缺席時優雅降級(回 False 並註記)。

用法:
  python3 collect_signals.py --base origin/main            # 在 git repo / CI 內
  python3 collect_signals.py --files a.py appsettings.json  # 本地測試,手動給變更檔
  選項: --difftext-file diff.txt  --aidf aidf_signals.json
"""
import argparse, json, os, re, shutil, subprocess, sys

SECRET_RE = re.compile(r'(?i)(api[_-]?key\s*[=:]|secret\s*[=:]|password\s*[=:]|bearer\s+[A-Za-z0-9._-]{12,}'
                       r'|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]{10,})')
# committed 對稱/簽章金鑰(鍵名脈絡 + 高熵字面值)— SECRET_RE 認不出 Aes256Key 之類鍵名的盲點(L3 CK1 為權威版)
CRYPTO_KEY_RE = re.compile(r'(?i)([\w.\-]*(?:aes\d*|encrypt(?:ion)?|crypto|cipher|signing|hmac|master|secret|private)[\w.\-]*key[\w.\-]*)'
                           r'\s*[:=]\s*["\']?([A-Za-z0-9+/]{32,}={0,2}|[0-9a-fA-F]{40,})["\']?')
DEP_FILES = ("requirements.txt","pyproject.toml","package.json","package-lock.json","go.mod",
             "packages.config","pom.xml","build.gradle")
ID_PAT  = re.compile(r'(?i)(entra|oidc|federat|rbac|roleassignment|azuread|client_id|tenant_id|\.bicep$|az login|azure/login)')
DB_PAT  = re.compile(r'(?i)(connectionstring|connection_string|sqlconnection|pyodbc|psycopg|mysql\.connector|mongoclient|database_url|sqlalchemy|appsettings.*[Cc]onnection)')
PII_PAT = re.compile(r'(?i)(student|rent|tenant|email|phone|id[_-]?number|personal|身分|個資|姓名|電話)')
DEPCSP  = re.compile(r'\.csproj$')
IAC_FILE= re.compile(r'(\.bicep$|\.tf$|main\.json$|azuredeploy.*\.json$)', re.I)
IAC_RES = re.compile(r'(?i)(resource\s+\w|azurerm_|"type"\s*:\s*"Microsoft\.|Microsoft\.(Web|Sql|Storage|DBfor\w+|KeyVault|DocumentDB))')
IMPORT_PAT=re.compile(r'(?i)(seed|import|匯入|roster|bulk[_-]?insert|users?\.csv|students?\.csv|accounts?\.(csv|json)|load_users|import_users)')
LOG_PAT = re.compile(r'(?i)(applicationinsights|log\s*analytics|diagnosticsettings|serilog|nlog|audit\s*log|access\s*log|logging\b|稽核|存取紀錄)')

def sh(cmd):
    try: return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except Exception: return ""

def changed_files(base):
    out = sh(["git","diff","--name-only",f"{base}...HEAD"]) or sh(["git","diff","--name-only",base])
    return [l.strip() for l in out.splitlines() if l.strip()]

def diff_text(base):
    return sh(["git","diff",f"{base}...HEAD"]) or sh(["git","diff",base])

def gitleaks_found():
    if not shutil.which("gitleaks"): return None
    try:
        subprocess.check_output(["gitleaks","detect","--no-banner","--report-format","json",
                                 "--report-path","/tmp/gl.json"], stderr=subprocess.DEVNULL)
        return False
    except subprocess.CalledProcessError:
        try: return len(json.load(open("/tmp/gl.json")))>0
        except Exception: return True
    except Exception: return None

def semgrep_high(files):
    """只掃 PR 變更檔(符合 PR 語意);無檔或 semgrep 缺席則回 None。"""
    if not shutil.which("semgrep"): return None
    scan=[f for f in files if os.path.exists(f)]
    if not scan: return False
    out=sh(["semgrep","--config","auto","--json","--quiet",*scan])
    try:
        res=json.loads(out).get("results",[])
        return any((r.get("extra",{}).get("severity","")).upper() in ("ERROR","HIGH") for r in res)
    except Exception: return None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--base", default=os.environ.get("COMPLIGATE_BASE","origin/main"))
    ap.add_argument("--files", nargs="*")
    ap.add_argument("--difftext-file")
    ap.add_argument("--aidf", help="P12 reasoner 輸出 JSON(含 complicit_oracle/tool_error/rewrite_churn)")
    ap.add_argument("--l3", help="L3 認證 oracle 輸出 JSON(含 identity_auth_fail/db_auth_fail)")
    a=ap.parse_args()

    files = a.files if a.files is not None else changed_files(a.base)
    dt = open(a.difftext_file).read() if a.difftext_file else ("" if a.files is not None else diff_text(a.base))
    notes=[]

    gl = gitleaks_found()
    secret = (gl is True) or bool(SECRET_RE.search(dt))
    if gl is None: notes.append("gitleaks not installed -> regex fallback for secret_in_diff")
    sg = semgrep_high(files)
    if sg is None: notes.append("semgrep not installed -> sast_high=False")

    sig = {
      "secret_in_diff": bool(secret),
      "crypto_key_in_diff": bool(CRYPTO_KEY_RE.search(dt)),  # 平面字面值;巢狀 JSON 由 L3 CK1 補(--l3 覆蓋)
      "new_dependency": any(f.endswith(DEP_FILES) or DEPCSP.search(f) for f in files),
      "high_cve": os.environ.get("COMPLIGATE_HIGH_CVE","false").lower()=="true",  # 由 SCA 步驟設定
      "identity_change": any(ID_PAT.search(f) for f in files) or bool(ID_PAT.search(dt)),
      "db_conn_change": any(DB_PAT.search(f) for f in files) or bool(DB_PAT.search(dt)),
      "pii_flow": any(PII_PAT.search(f) for f in files),
      "sast_high": bool(sg) if sg is not None else False,
      "cloud_resource_provision": any(IAC_FILE.search(f) for f in files) or bool(IAC_RES.search(dt)),
      "identity_data_import": any(IMPORT_PAT.search(f) for f in files) or bool(IMPORT_PAT.search(dt)),
      "access_logging_change": any(LOG_PAT.search(f) for f in files) or bool(LOG_PAT.search(dt)),
    }
    if a.aidf and os.path.exists(a.aidf):
        try:
            aj=json.load(open(a.aidf))
            for k in ("complicit_oracle","tool_error","rewrite_churn"):
                if k in aj: sig[k]=bool(aj[k])
        except Exception: notes.append("could not parse --aidf")
    else:
        notes.append("no AIDF input (--aidf) -> L4 signals default False")

    if a.l3 and os.path.exists(a.l3):
        try:
            lj=json.load(open(a.l3)).get("signals",{})
            for k,v in lj.items(): sig[k]=bool(v) or sig.get(k,False)  # L3 oracle 較權威,fail 為真即覆蓋
            notes.append("L3 auth oracle merged")
        except Exception: notes.append("could not parse --l3")
    else:
        notes.append("no L3 input (--l3) -> identity/db auth verified only heuristically")

    print(json.dumps({"signals":sig,"changed_files":files,"notes":notes}, ensure_ascii=False))

if __name__=="__main__": main()
