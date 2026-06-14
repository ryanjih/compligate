#!/usr/bin/env python3
"""L3 認證 oracle (C4) — 對 PR 變更的 Entra/OIDC/RBAC 與雲地端 DB 設定做確定性安全檢核。
FAIL = 真實 deployment-locus 失效 → 產出 identity_auth_fail / db_auth_fail signals,
並把每筆 (check, pass/fail) 記入 deployment_locus_dataset.jsonl(C4 語料,回填 P12 缺口)。
輸出 l3_signals.json 給 collect_signals --l3。
"""
import argparse, json, os, re

IDFILE = re.compile(r'(\.github/workflows/.*\.ya?ml$|\.bicep$|\.tf$|appsettings.*\.json$|main\.json$)', re.I)
DBFILE = re.compile(r'(appsettings.*\.json$|\.env$|web\.config$|\.tf$|\.bicep$|\.cs$|\.py$|\.ts$|\.js$)', re.I)

# --- 偵測器(regex over 檔案內容) ---
RE_OIDC_LOGIN   = re.compile(r'azure/login|az\s+login|AzureCLI|managedidentity|federatedcredential', re.I)
RE_CLIENT_SECRET= re.compile(r'(?i)(client[_-]?secret|AZURE_CLIENT_SECRET|"password"\s*:|clientSecret\s*[:=])')
RE_BROAD_SUBJECT= re.compile(r'(?i)subject[^\n]{0,80}(repo:[^"\n]*\*|:ref:refs/heads/\*|environment:\*)')
RE_RBAC_OWNER   = re.compile(r'(?i)\b(Owner|Contributor)\b')
RE_SUB_SCOPE    = re.compile(r'(?i)/subscriptions/[0-9a-f-]+(?=$|["\'\s])')  # 訂閱級 scope(後接結束/引號/空白,非 /resourceGroups)
RE_CONNSTR      = re.compile(r'(?i)(connectionstring|server\s*=|data source\s*=|host\s*=|sqlconnection|database_url)')
RE_PLAINTEXT_PW = re.compile(r'(?i)(password|pwd)\s*=\s*[^;"\'\s]{3,}')
RE_MI_OR_KV     = re.compile(r'(?i)(Authentication\s*=\s*Active Directory|@Microsoft\.KeyVault|Managed Identity|DefaultAzureCredential)')
RE_NO_TLS       = re.compile(r'(?i)(Encrypt\s*=\s*false|sslmode\s*=\s*disable|TrustServerCertificate\s*=\s*true)')
# --- committed 對稱/簽章金鑰偵測(CK,A.8.24)——堵 SECRET_RE 認不出 Aes256Key 之類鍵名的盲點 ---
RE_CRYPTO_NAME  = re.compile(r'(?i)(aes\d*|encrypt(?:ion)?|crypto|cipher|signing|hmac|master|secret|private)[_-]?key')
RE_CRYPTO_FILE  = re.compile(r'(\.(json|ya?ml|env|cs|py|ts|js|config|xml|properties|toml)$|appsettings)', re.I)
RE_CRYPTO_INLINE= re.compile(r'(?i)([\w.\-]*(?:aes\d*|encrypt(?:ion)?|crypto|cipher|signing|hmac|master|secret|private)[\w.\-]*key[\w.\-]*)'
                             r'\s*[:=]\s*["\']?([A-Za-z0-9+/]{32,}={0,2}|[0-9a-fA-F]{40,})["\']?')

def read(root,f):
    try: return open(os.path.join(root,f),encoding="utf-8",errors="ignore").read()
    except Exception: return ""

def _strip_comments(c):
    return "\n".join(l for l in c.splitlines() if not l.lstrip().startswith(("#","//","*","<!--")))

def check_identity(f, c):
    c=_strip_comments(c)   # 略過註解行,避免「no client-secret」等說明造成誤報
    out=[]
    touches = bool(IDFILE.search(f) and (RE_OIDC_LOGIN.search(c) or RE_CLIENT_SECRET.search(c) or "roleassignment" in c.lower() or RE_BROAD_SUBJECT.search(c)))
    if not touches: return out
    # ID1 secretless(OIDC) — 不得有 client secret/明文密碼
    out.append(dict(check="ID1_secretless_oidc", req="GitHub→Azure 須用 OIDC 聯邦,不得用 client secret",
                    control="A.5.15", status="fail" if RE_CLIENT_SECRET.search(c) else "pass",
                    locus="deployment", failure_mode="auth_credential_failure"))
    # ID2 federated subject 綁定(不得 wildcard)
    out.append(dict(check="ID2_subject_binding", req="Federated credential subject 須綁定 repo/ref,不得 wildcard",
                    control="A.5.16", status="fail" if RE_BROAD_SUBJECT.search(c) else "pass",
                    locus="deployment", failure_mode="auth_credential_failure"))
    # ID3 RBAC 最小權限(不得 subscription 級 Owner/Contributor)
    overpriv = bool(RE_RBAC_OWNER.search(c) and RE_SUB_SCOPE.search(c))
    out.append(dict(check="ID3_least_privilege", req="RBAC 須最小權限,不得 subscription 級 Owner/Contributor",
                    control="A.8.2", status="fail" if overpriv else "pass",
                    locus="deployment", failure_mode="auth_credential_failure"))
    return out

def check_db(f, c):
    c=_strip_comments(c)
    out=[]
    if not (DBFILE.search(f) and RE_CONNSTR.search(c)): return out
    has_pw = bool(RE_PLAINTEXT_PW.search(c)); has_mi = bool(RE_MI_OR_KV.search(c))
    # DB1 不得明文憑證(應用 managed identity / Key Vault)
    out.append(dict(check="DB1_no_plaintext_cred", req="DB 連線不得含明文憑證,應用 managed identity / Key Vault",
                    control="A.8.24", status="fail" if (has_pw and not has_mi) else "pass",
                    locus="deployment", failure_mode="auth_credential_failure"))
    # DB2 強制傳輸加密
    out.append(dict(check="DB2_tls_enforced", req="DB 連線須強制 TLS(不得 Encrypt=false / sslmode=disable)",
                    control="A.8.21", status="fail" if RE_NO_TLS.search(c) else "pass",
                    locus="deployment", failure_mode="auth_credential_failure"))
    return out

def _is_key_material(s):
    """高熵 base64(>=32)或 hex(>=40) 字面值,且字元多樣(排除佔位符如 xxxx../AAAA..)。"""
    s=str(s)
    if len(s)<32: return False
    if re.fullmatch(r'[A-Za-z0-9+/]{32,}={0,2}', s) or re.fullmatch(r'[0-9a-fA-F]{40,}', s):
        return len(set(s))>=12
    return False

def _walk_json_keys(obj, under_crypto, path, hits):
    """遞迴走 JSON;凡祖先鍵名命中 RE_CRYPTO_NAME 且葉節點為金鑰材料 -> 記(路徑,長度),不取值。"""
    if isinstance(obj, dict):
        for k,v in obj.items():
            nxt = under_crypto or bool(RE_CRYPTO_NAME.search(str(k)))
            _walk_json_keys(v, nxt, f"{path}.{k}" if path else str(k), hits)
    elif isinstance(obj, list):
        for i,v in enumerate(obj): _walk_json_keys(v, under_crypto, f"{path}[{i}]", hits)
    elif under_crypto and isinstance(obj,str) and _is_key_material(obj):
        hits[path]=len(obj)

def check_crypto_keys(f, c):
    """CK1:加密/簽章金鑰不得提交進版控(A.8.24)。需有 crypto 鍵名脈絡才評估(高精準)。"""
    if not RE_CRYPTO_FILE.search(f): return []
    cc=_strip_comments(c)
    if not RE_CRYPTO_NAME.search(cc): return []          # 無 crypto 鍵名脈絡 -> 不評估,避免誤報
    hits={}
    for m in RE_CRYPTO_INLINE.finditer(cc):              # 平面: Aes256Key="..." / EncryptionKey=hex
        if "@microsoft.keyvault" not in m.group(0).lower(): hits[m.group(1).strip(' "\'')]=len(m.group(2))
    if f.lower().endswith(".json") or "appsettings" in f.lower():
        try: _walk_json_keys(json.loads(c), False, "", hits)   # 巢狀: Aes256Key:{1:..,2:..}
        except Exception: pass
    status="fail" if hits else "pass"
    detail="; ".join(f"{k}(len={v})" for k,v in hits.items()) if hits else "crypto 鍵名存在但未見提交金鑰材料(KeyVault/空/env)"
    return [dict(check="CK1_no_committed_crypto_key", control="A.8.24", status=status,
                 req="加密/簽章金鑰不得提交進版控,須置於 Key Vault / 受管金鑰(A.8.24)",
                 locus="deployment", failure_mode="crypto_key_exposure", detail=detail)]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--changed-files",nargs="*",default=[])
    ap.add_argument("--repo-root",default=".")
    ap.add_argument("--out",default="l3_signals.json")
    ap.add_argument("--c4-dataset",default="deployment_locus_dataset.jsonl")
    a=ap.parse_args()
    checks=[]
    for f in a.changed_files:
        c=read(a.repo_root,f)
        checks += [{**x,"file":f} for x in check_identity(f,c)]
        checks += [{**x,"file":f} for x in check_db(f,c)]
        checks += [{**x,"file":f} for x in check_crypto_keys(f,c)]
    id_fail = any(x["status"]=="fail" and x["control"] in ("A.5.15","A.5.16","A.8.2") for x in checks)
    db_fail = any(x["status"]=="fail" and x["check"] in ("DB1_no_plaintext_cred","DB2_tls_enforced") for x in checks)
    crypto_fail = any(x["status"]=="fail" and x["check"]=="CK1_no_committed_crypto_key" for x in checks)
    sig={"identity_change": any(x["control"].startswith("A.5") or x["control"]=="A.8.2" for x in checks),
         "db_conn_change": any(x["check"] in ("DB1_no_plaintext_cred","DB2_tls_enforced") for x in checks),
         "identity_auth_fail": id_fail, "db_auth_fail": db_fail, "crypto_key_in_diff": crypto_fail}
    out={"signals":sig,"l3_checks":checks,
         "notes":[f"{sum(1 for x in checks if x['status']=='fail')} fail / {len(checks)} L3 checks"]}
    open(a.out,"w",encoding="utf-8").write(json.dumps(out,ensure_ascii=False,indent=2))
    # C4 deployment-locus 語料(每個 check 一筆,gt_failure = (status==fail))
    import datetime
    with open(a.c4_dataset,"a",encoding="utf-8") as fh:
        for x in checks:
            fh.write(json.dumps({"ts":datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "locus":"deployment","check":x["check"],"file":x["file"],"control":x["control"],
                "failure_mode":x["failure_mode"],"gt_failure":1 if x["status"]=="fail" else 0},ensure_ascii=False)+"\n")
    print(json.dumps(out,ensure_ascii=False))

if __name__=="__main__": main()
