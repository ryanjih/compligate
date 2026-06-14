#!/usr/bin/env python3
"""Synthetic secret-detection benchmark (v2) — deterministic, released.
Classes:
  crypto_pos          : committed cryptographic key material under crypto-named keys (detection POSITIVE)
  crypto_lookalike_neg: crypto-named look-alikes that are NOT key material (detection hard NEGATIVE)
  generic_secret      : committed non-crypto secrets/tokens (gate should-block; NOT the crypto-key class)
  benign_other        : no secret at all (negative everywhere)
Split: each class is partitioned into 'dev' (design/tuning) and 'test' (held-out, reported).
All key material is SYNTHETIC (seeded PRNG). Values are illustrative, not real secrets."""
import os, base64, random, json
HERE=os.path.dirname(os.path.abspath(__file__)); COR=os.path.join(HERE,"corpus")
import shutil
if os.path.isdir(COR): shutil.rmtree(COR)
os.makedirs(COR)
rng=random.Random(20260614)
def hb(n): return bytes(rng.getrandbits(8) for _ in range(n))
def b64(n=32): return base64.b64encode(hb(n)).decode()
def hexk(n=32): return hb(n).hex()
def lowent_b64():  # valid-looking but low-distinct (entropy) base64-ish
    return base64.b64encode(bytes([65,66]* 24)).decode()  # 'ABAB...' low distinct
F={}; meta={}
def add(name,content,cls,split): F[name]=content; meta[name]={"class":cls,"split":split}

NAMES=["Aes256Key","EncryptionKey","HmacKeys","SigningKey","MasterKey","CipherKey","PrivateKey","aes_key","hmac_signing_key","secretKey"]
# ---- crypto_pos (24): vary structure/encoding/name; ~3 hard positives CK1 may miss ----
i=0
def sp(idx): return "dev" if idx%5<2 else "test"   # ~40% dev / 60% test
# nested JSON (several)
for k in range(6):
    nm=NAMES[k%len(NAMES)]; add(f"p{i:02d}_appsettings_{k}.json",json.dumps({"App":"x",nm:{"1":b64(),"2":b64()}},indent=2),"crypto_pos",sp(i)); i+=1
# deep nested json
add(f"p{i:02d}_deep.json",json.dumps({"security":{"crypto":{"aesKey":{"primary":b64()}}}},indent=2),"crypto_pos",sp(i)); i+=1
# flat json b64 & hex
for k in range(4):
    nm=NAMES[(k+2)%len(NAMES)]; v=b64() if k%2 else hexk(); add(f"p{i:02d}_flat_{k}.json",json.dumps({nm:v}),"crypto_pos",sp(i)); i+=1
# nested YAML
add(f"p{i:02d}_secrets.yaml","svc: api\nsigningKey:\n  current: "+hexk()+"\n","crypto_pos",sp(i)); i+=1
add(f"p{i:02d}_enc.yaml","encryptionKey:\n  v1: "+b64()+"\n","crypto_pos",sp(i)); i+=1
# flat YAML
add(f"p{i:02d}_keys.yaml","aes_key: "+b64()+"\n","crypto_pos",sp(i)); i+=1
# TOML flat + subtable
add(f"p{i:02d}_settings.toml","[crypto]\nmaster_key = \""+hexk()+"\"\n","crypto_pos",sp(i)); i+=1
add(f"p{i:02d}_sub.toml","[security.crypto]\naes_key = \""+b64()+"\"\n","crypto_pos",sp(i)); i+=1
# env, cs, properties, xml, config
add(f"p{i:02d}_app.env","DEBUG=1\nHMAC_SIGNING_KEY="+b64()+"\n","crypto_pos",sp(i)); i+=1
add(f"p{i:02d}_Crypto.cs","class C{ const string EncryptionKey=\""+b64()+"\"; }\n","crypto_pos",sp(i)); i+=1
add(f"p{i:02d}_app.properties","aes.encryption.key="+b64()+"\n","crypto_pos",sp(i)); i+=1
add(f"p{i:02d}_web.config","<configuration><appSettings><add key=\"AesKey\" value=\""+b64()+"\"/></appSettings></configuration>\n","crypto_pos",sp(i)); i+=1
# hard positives (CK1 likely MISSES -> honest recall): low-entropy real key, split string, Unicode name
add(f"p{i:02d}_lowentropy.json",json.dumps({"AesKey":lowent_b64()}),"crypto_pos",sp(i)); i+=1
add(f"p{i:02d}_split.cs","var k=\""+b64(16)+"\"+\""+b64(16)+"\"; // EncryptionKey assembled\n","crypto_pos",sp(i)); i+=1
add(f"p{i:02d}_unicode.json",json.dumps({"加密金鑰":b64()},ensure_ascii=False),"crypto_pos",sp(i)); i+=1
NPOS=i
# ---- crypto_lookalike_neg (22): crypto NAME but NOT key material ----
def addn(tag,content,cls="crypto_lookalike_neg"):
    global i; add(f"n{i:02d}_{tag}",content,cls,sp(i)); i+=1
addn("version.json",json.dumps({"Aes256Key":{"1":"1.2.3","2":"1.2.4"}}))
addn("keyvault.json",json.dumps({"EncryptionKey":"@Microsoft.KeyVault(SecretUri=https://v.vault.azure.net/s/x)"}))
addn("envref.json",json.dumps({"AesKey":"${AES_KEY}"}))
addn("envref2.yaml","signingKey: \"#{SIGNING_KEY}#\"\n")
addn("placeholder1.json",json.dumps({"SigningKey":"x"*44}))
addn("placeholder2.json",json.dumps({"MasterKey":"changeme"}))
addn("placeholder3.json",json.dumps({"CipherKey":"your-key-here"}))
addn("guid.json",json.dumps({"MasterKey":"550e8400-e29b-41d4-a716-446655440000"}))
addn("path.json",json.dumps({"PrivateKeyPath":"/etc/ssl/private/key.pem"}))
addn("empty.yaml","encryptionKey: \"\"\n")
addn("short.json",json.dumps({"Aes256Key":"shortvalue"}))
addn("shorthex.json",json.dumps({"CipherKey":"abcdef0123"}))
addn("commented.cs","// EncryptionKey = \""+b64()+"\"  (rotated)\n")
addn("hash_checksum.json",json.dumps({"fileChecksum":hexk(32)}))   # high-entropy hex but NON-crypto name (checksum)
addn("buildhash.yaml","buildHash: "+hexk(20)+"\n")
addn("disabled.json",json.dumps({"Aes256Key":None}))
addn("ref_only.json",json.dumps({"EncryptionKeyRef":"secret://aes-key"}))
addn("comment_yaml.yaml","# aes_key: "+b64()+"\nservice: api\n")
addn("template.json",json.dumps({"SigningKey":"{{ SIGNING_KEY }}"}))
addn("desc.json",json.dumps({"note":"set EncryptionKey via Key Vault, never commit"}))
addn("numbered.json",json.dumps({"keyVersion":"3"}))
addn("falsekeyname.json",json.dumps({"monkey":b64(),"donkey":hexk()}))  # 'key' substring but not crypto
# ---- generic_secret (8): committed non-crypto secret/token (gate should-block; not crypto class) ----
def addg(tag,content):
    global i; add(f"g{i:02d}_{tag}",content,"generic_secret",sp(i)); i+=1
addg("apitoken.json",json.dumps({"ApiToken":b64()}))
addg("apikey.env","API_KEY="+b64()+"\n")
addg("password.json",json.dumps({"db":{"password":b64(12)}}))
addg("bearer.txt","Authorization: Bearer "+b64()+"\n")
addg("awskey.txt","aws_secret_access_key = "+b64(30)+"\n")
addg("jwt.env","SESSION_JWT=eyJhbGciOiJIUzI1Ni',"+b64()+"\n")
addg("conn.cs","var c=\"Server=db;User=sa;Password="+b64(12)+";\";\n")
addg("slack.txt","slack_token="+b64()+"\n")
# ---- benign_other (8) ----
def addb(tag,content):
    global i; add(f"b{i:02d}_{tag}",content,"benign_other",sp(i)); i+=1
addb("config.json",json.dumps({"logging":{"level":"info"},"timeout":30}))
addb("readme.md","# Project\nRun `make build`. Configure keys via Key Vault.\n")
addb("util.py","def add(a,b):\n    return a+b\n")
addb("app.yaml","service: web\nreplicas: 3\nport: 8080\n")
addb("data.json",json.dumps({"users":[{"name":"a"},{"name":"b"}]}))
addb("style.css","body { margin: 0; color: #333; }\n")
addb("pkg.json",json.dumps({"name":"app","version":"1.0.0","deps":{}}))
addb("notes.txt","TODO: rotate credentials quarterly via Key Vault.\n")
for fn,c in F.items(): open(os.path.join(COR,fn),"w",encoding="utf-8").write(c)
json.dump(meta,open(os.path.join(HERE,"labels.json"),"w"),indent=2,ensure_ascii=False)
from collections import Counter
cc=Counter(m["class"] for m in meta.values()); ss=Counter((m["class"],m["split"]) for m in meta.values())
print("files:",len(F)); 
for c in ("crypto_pos","crypto_lookalike_neg","generic_secret","benign_other"):
    print(f"  {c:22} total={cc[c]:3}  dev={ss[(c,'dev')]:2} test={ss[(c,'test')]:2}")
