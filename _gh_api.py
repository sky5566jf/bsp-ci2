# -*- coding: utf-8 -*-
"""最小 GitHub API 客户端（只做本项目 CI 需要的那几步），token 从 git remote 里取，
永不打印 token 本身。

用法:
  python _gh_api.py info
  python _gh_api.py public|private
  python _gh_api.py runs [N]
  python _gh_api.py wait <timeout_sec>
  python _gh_api.py dl <run_id> <out_dir>
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import zipfile

D = os.path.dirname(os.path.abspath(__file__))
OWNER, REPO = 'sky5566jf', 'bsp-ci2'
API = 'https://api.github.com'


def _tok():
    url = subprocess.check_output(['git', 'config', '--get', 'remote.origin.url'],
                                  cwd=D).decode().strip()
    m = re.search(r'://([^@/]+)@', url)
    if not m:
        raise SystemExit('remote url has no credential')
    cred = m.group(1)
    return cred.split(':')[-1] if ':' in cred else cred


TOK = _tok()
HDR = {'Authorization': 'Bearer ' + TOK, 'Accept': 'application/vnd.github+json',
       'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'bsp-ci'}


def req(method, path, data=None, raw=False):
    url = path if path.startswith('http') else API + path
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, method=method, headers=HDR)
    if body:
        r.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            b = resp.read()
            return resp.status, (b if raw else json.loads(b or b'{}'))
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:300]


def cmd_info():
    st, d = req('GET', '/repos/%s/%s' % (OWNER, REPO))
    print('repo=%s/%s http=%s private=%s default=%s'
          % (OWNER, REPO, st, d.get('private'), d.get('default_branch')))
    st, d = req('GET', '/repos/%s/%s/actions/permissions' % (OWNER, REPO))
    print('actions_allowed http=%s' % st)


def cmd_vis(want_private):
    st, d = req('PATCH', '/repos/%s/%s' % (OWNER, REPO), {'private': want_private})
    print('PATCH private=%s http=%s now=%s' % (want_private, st, d.get('private')))


def cmd_runs(n=5):
    st, d = req('GET', '/repos/%s/%s/actions/runs?per_page=%d' % (OWNER, REPO, int(n)))
    if st != 200:
        print('runs http=%s %r' % (st, d))
        return []
    out = []
    for r in d.get('workflow_runs', []):
        print('run %s sha=%s status=%s concl=%s created=%s'
              % (r['id'], (r['head_sha'] or '')[:8], r['status'],
                 r.get('conclusion'), r['created_at']))
        out.append(r['id'])
    return out


def cmd_wait(timeout=900, sha=None):
    t0 = time.time()
    seen = None
    while time.time() - t0 < timeout:
        st, d = req('GET', '/repos/%s/%s/actions/runs?per_page=3' % (OWNER, REPO))
        if st == 200 and d.get('workflow_runs'):
            r = d['workflow_runs'][0]
            if sha and (r['head_sha'] or '')[:8] != sha[:8]:
                time.sleep(10)
                continue
            seen = r
            if r['status'] == 'completed':
                print('DONE run=%s concl=%s sha=%s'
                      % (r['id'], r.get('conclusion'), (r['head_sha'] or '')[:8]))
                return r['id'], r.get('conclusion')
        time.sleep(10)
    print('TIMEOUT last=%s' % (seen and (seen['id'], seen['status'])))
    return None, None


def cmd_dl(run_id, outdir):
    os.makedirs(outdir, exist_ok=True)
    st, b = req('GET', '/repos/%s/%s/actions/runs/%s/artifacts'
                % (OWNER, REPO, run_id))
    arts = (b or {}).get('artifacts', []) if isinstance(b, dict) else []
    if not arts:
        print('no artifacts http=%s %r' % (st, b))
        return 1
    a = arts[0]
    print('artifact=%s size=%s' % (a['name'], a['size_in_bytes']))

    class _NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kw):
            return None

    # 关键：artifacts 的下载地址会 302 到 S3 签名 URL。带着 Authorization 去跟跳转
    # 会被 S3 拒（签名 + Authorization 冲突 → 401）。必须先拿 Location，再裸取。
    op = urllib.request.build_opener(_NoRedir)
    r = urllib.request.Request(a['archive_download_url'], headers=HDR)
    loc = ''
    try:
        with op.open(r, timeout=60) as resp:
            loc = resp.headers.get('Location') or ''
    except urllib.error.HTTPError as e:
        loc = e.headers.get('Location') or ''
        if not loc:
            print('download http=%s body=%r' % (e.code, e.read()[:200]))
            return 1
    if not loc:
        print('no redirect location')
        return 1
    blob = urllib.request.urlopen(loc, timeout=120).read()
    zp = os.path.join(outdir, 'dylibs.zip')
    open(zp, 'wb').write(blob)
    with zipfile.ZipFile(zp) as z:
        names = z.namelist()
        z.extractall(outdir)
    print('downloaded %d B files=%s' % (len(blob), names))
    return 0


if __name__ == '__main__':
    a = sys.argv[1:]
    if not a:
        raise SystemExit(__doc__)
    c = a[0]
    if c == 'info':
        cmd_info()
    elif c == 'public':
        cmd_vis(False)
    elif c == 'private':
        cmd_vis(True)
    elif c == 'runs':
        cmd_runs(a[1] if len(a) > 1 else 5)
    elif c == 'wait':
        cmd_wait(int(a[1]) if len(a) > 1 else 900, a[2] if len(a) > 2 else None)
    elif c == 'dl':
        sys.exit(cmd_dl(a[1], a[2]))
    else:
        raise SystemExit(__doc__)
