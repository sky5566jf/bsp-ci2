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
        # ★ v6.7 落盘后自动重启（STOP → 等 state 归零 → START → 等 run=1）
        'g_autoreload', 'g_need_reload', 'g_reload_busy', 'OPER_START',
        'RL_IDLE', 'RL_WAIT_ZERO', 'RL_WAIT_RUN', 'RL_ZERO_TICKS', 'RL_RUN_TICKS',
        'autoreload', 'auto-reload',
        # ★ v6.8 下载长超时 + 重载键对齐
        'bs_http_get_ex_tmo', 'SO_DL_TMO_REQ', 'SO_DL_TMO_RES',
        'RL_KEY_TICKS', 'g_rl_ver', 'holding START until key',
        'not injected after',
        # ★ v6.9~v6.13 局域网中继分流（少一块补一块，之前漏登记）
        'SO_PORT_DEF', 'sohost', 'soport',
        # ★ v6.14 密钥被产品整表替换后自愈（判据反转 + 进程内缓存）
        'bs_mh_count', 'g_mh_kk', 'g_mh_vv', 'g_mh_cached', 're-inject from cache',
        # ★ v6.15 beta.so 多记录容器 ⇒ 补注「载荷记录版本 020909」密钥
        'bs_ensure_payload_key', 'g_pay_vv', 'g_pay_cached', 'g_pay_miss', 'g_pay_try',
        'payload cloud key OK', 'payload key injected',
        # ★ v6.39 断网恢复自启四件套
        'HB_FAST_SECS', 'HB_FAST_RETRY', 'AR_KILL_COOL_NET', 'g_kill_resumable',
        'heartbeat lost (max misses)', 'kill-cool-net', 'hb_fast']
print('---- symbols ----')
for k in need:
    c = src.count(k)
    flag = 'OK ' if c else 'MISSING'
    if not c:
        bad += 1
    print('%-30s %2d  %s' % (k, c, flag))

print('---- size ---- %d bytes' % len(src))
sys.exit(1 if bad else 0)
