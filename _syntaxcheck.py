#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""粗粒度 C 语法自检：剥离注释/字符串后做括号平衡 + 关键符号存在性检查。
Windows 本机无 clang，真编译走 macOS CI；这里只做提交前的防呆。"""
import sys, os

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bs_unlock.m')
BS = chr(92)          # 反斜杠
src = open(SRC, encoding='utf-8', errors='replace').read()

out = []
i, n = 0, len(src)
instr = None
incom = None
while i < n:
    c = src[i]
    if incom:
        if incom == '//' and c == '\n':
            incom = None
        elif incom == '/*' and src[i:i+2] == '*/':
            incom = None
            i += 2
            continue
        i += 1
        continue
    if instr:
        if c == BS:
            i += 2
            continue
        if c == instr:
            instr = None
        i += 1
        continue
    two = src[i:i+2]
    if two == '//':
        incom = '//'; i += 2; continue
    if two == '/*':
        incom = '/*'; i += 2; continue
    if c == '"':
        instr = '"'; i += 1; continue
    if c == "'":
        instr = "'"; i += 1; continue
    out.append(c)
    i += 1

code = ''.join(out)
bad = 0
for op, cl, name in [('{', '}', 'brace'), ('(', ')', 'paren'), ('[', ']', 'bracket')]:
    a, b = code.count(op), code.count(cl)
    ok = (a == b)
    if not ok:
        bad += 1
    print('%-8s %4d / %-4d %s' % (name, a, b, 'OK' if ok else '*** MISMATCH ***'))

need = ['bs_hb_ping', 'bs_killswitch', 'bs_http_get_ex', 'g_hb_ok', 'g_hb_miss',
        'g_hb_last', 'g_mod_dir', 'HB_PATH', 'HB_MISS_MAX_DEF', 'g_hb_max',
        'hbmiss', 'dirent.h', 'errno.h',
        'script stopped (run 1->0)', 'heartbeat lost',
        # ★ v6.3 密钥云端化
        'bs_inject_mh', 'bs_read_beta_ver', 'BS_PRJ', 'cloud key OK',
        # ★ v6.4 probe 模式（真卡机只读雷达）
        'PROBE_PATH', 'MODE_PROBE', 'g_mode', 'bs_probe_thread',
        'bs_http_post_ex', 'bs_mh_snapshot', 'bs_read_file', 'bs_hex3',
        'BSPR', 'PROBE mode',
        # ★ v6.5 版本跃迁自愈（版本哨兵 + 按版本幂等注入）
        'bs_verwatch', 'VERWATCH_TICK_SECS', 'VERWATCH_RETRY_EVERY', 'g_mh_ver',
        'g_mh_miss', 'g_mh_try', 'bs_mh_has', 'bs_verhex_to_bytes',
        'ver changed', 'hold old',
        # ★ v6.6 主动跟版（云端 /ver + /script/beta.so 落盘）
        'bs_so_sync_once', 'bs_so_sync_thread', 'bs_write_file_atomic',
        'bs_json_pick_ver', 'bs_json_has_true', 'SO_VER_PATH',
        'g_so_sync', 'g_so_tick', 'sync.tmp', 'has_key',
        # ★ v6.7 契约：脚本只认「本来在跑」和「中控手动下发」，autoreload 开关仍在，
        #   但 v6.24q 已把落盘自动重载的**状态机**整条删除（RL_IDLE/RL_WAIT_* 等常量
        #   随之消失）。旧断言留着只会永远 MISSING、把本脚本变成恒 exit 1 的摆设，
        #   v6.40 一并清理。
        'g_autoreload', 'g_need_reload', 'g_reload_busy', 'OPER_START',
        'autoreload',
        # ★ v6.8 下载长超时 + 重载键对齐
        'bs_http_get_ex_tmo', 'SO_DL_TMO_REQ', 'SO_DL_TMO_RES',
        'RL_KEY_TICKS', 'g_rl_ver',
        # ★ v6.24q 起「落盘后自动重载」整条链路已删（脚本只认「本来在跑」和
        #   「中控手动下发」两种运行，不许自己重载）—— 旧的两条断言长期 MISSING，
        #   等于把本脚本废掉（永远 exit 1），v6.40 一并移除。
        # ★ v6.9~v6.13 局域网中继分流（少一块补一块，之前漏登记）
        'SO_PORT_DEF', 'sohost', 'soport',
        # ★ v6.14 密钥被产品整表替换后自愈（判据反转 + 进程内缓存）
        'bs_mh_count', 'g_mh_kk', 'g_mh_vv', 'g_mh_cached', 're-inject from cache',
        # ★ v6.15 beta.so 多记录容器 ⇒ 补注「载荷记录版本 020909」密钥
        'bs_ensure_payload_key', 'g_pay_vv', 'g_pay_cached', 'g_pay_miss', 'g_pay_try',
        'payload cloud key OK', 'payload key injected',
        # ★ v6.39 断网恢复自启四件套
        'HB_FAST_SECS', 'HB_FAST_RETRY', 'AR_KILL_COOL_NET', 'g_kill_resumable',
        'heartbeat lost (max misses)', 'kill-cool-net', 'hb_fast',
        # ★★★ v6.40 断网恢复不自启的真元凶：disarm 不认自己人
        'AR_KILL_SELF_WIN',                                # 自我认领窗口（900s）
        'stop evidence = OUR killswitch',                  # stall scan 认领
        'skip disarm (keep armed=',                        # 认领后的动作
        'stop evidence = network failure (kind=6)',        # kind=6 分类
        'center-stop is OUR killswitch',                   # 抑制矩阵放行
        'NOT gating, proceed',                             # 实时复查放行
        'tcp connect server timeout',                      # 网络故障签名
        'connect remote server',                           # 网络故障签名
        ]

# ★★★ v6.40 结构断言：光有字符串不够，必须确认保护**在正确的位置**。
#   v6.39 的真实教训就是「三处阻断只修了一处」—— 所以这里逐处点名。
struct_checks = [
    ('kind=6 分类存在',            'kind = netfail ? 6 : 2;'),
    ('us_stop 不吃 kind=6',        'us_latched || (ar_stop_kind == 2)'),
    ('disarm 分支认领',            'skip disarm (keep armed='),
    ('抑制矩阵认领',               'center-stop is OUR killswitch'),
    ('实时复查认领',               'NOT gating, proceed'),
    ('人停 disarm 仍在(未回归)',    'auto-resume OFF until next Run'),
    ('实时人停闸门仍在(未回归)',     'resume BLOCKED: live agent.log says center/user stop'),
]

print('---- symbols ----')
for k in need:
    c = src.count(k)
    flag = 'OK ' if c else 'MISSING'
    if not c:
        bad += 1
    print('%-30s %2d  %s' % (k, c, flag))

print('---- struct (v6.40 三处阻断逐处点名) ----')
for name, pat in struct_checks:
    c = src.count(pat)
    if not c:
        bad += 1
    print('%-28s %2d  %s' % (name, c, 'OK ' if c else 'MISSING'))

# ★ 反向断言：v6.24q 起这些串**绝不允许**出现（脚本只认两种运行，不许自己重载）
print('---- forbidden ----')
for pat in ['auto-reload: request STOP',
            'kept STOPPED, press Run in center',
            'TRIGGERED (%s) miss=%d -> stop script + wipe always']:
    c = src.count(pat)
    if c:
        bad += 1
    print('%-46s %2d  %s' % (pat[:46], c, 'OK ' if not c else 'FORBIDDEN'))

print('---- size ---- %d bytes' % len(src))
if bad:
    print('!! %d 项未通过' % bad)
sys.exit(1 if bad else 0)
