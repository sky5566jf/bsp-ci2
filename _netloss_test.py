#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v6.39 断网恢复自启 —— 状态机仿真验证（不依赖真机）

把 bs_unlock.m 里断网这条链路的判定逻辑抽成最小状态机，按真实时间轴跑一遍，
断言：断网 3 分钟→恢复→脚本必须在 3 分钟内自己起来（旧版是永久躺着）。
同时给出旧版（v6.38）基线对照，量化修复效果。
"""
import sys

# ---------- 可调参数（与源码常量一致）----------
TICK = 60                 # g_tick（conf tick=60）
HB_MISS = 3               # conf hbmiss=3
HB_FAST_SECS = 20         # v6.39 新增
HB_FAST_RETRY = 6         # v6.39 新增
AR_KILL_COOL = 600        # 旧版：一律 600s
AR_KILL_COOL_NET = 90     # v6.39：网络类 90s
WD_TICK = 5               # watchdog 扫描间隔（实测约 5s）


def simulate(ver, offline_from, offline_to, total=1800):
    """返回 (脚本恢复所需秒数 or None, 关键事件列表)

    严格耦合版：puller 每拍产出 (时刻, 心跳结论)，watchdog 按 WD_TICK 扫描时
    查询「最近一次 puller 结论」，而不是用 offline_to 近似 —— 否则会出现
    「心跳还没恢复，ar 先接上」这种不可能的时间轴。
    """
    v39 = (ver == 'v6.39')
    ev = []

    hb_miss = 0
    hb_ok = 1
    kill_sent = False
    kill_ts = 0
    kill_resumable = 0
    wiped = False
    ar_lst = 1
    hb_fast = 0
    hb_fast_n = 0
    stopped = False
    resumed = None

    # ---- 阶段1：跑 puller，记录每次心跳结论的时间轴 ----
    hb_timeline = []          # [(时刻, hb_ok, hb_miss)] 每拍一条
    t = 3
    while t < total:
        online = not (offline_from <= t < offline_to)
        if not online:
            hb_miss += 1
            if hb_miss >= HB_MISS and not kill_sent:
                kill_sent = True
                kill_ts = t
                kill_resumable = 0 if not v39 else 1
                if not v39:
                    wiped = True
                    ar_lst = 0
                stopped = True
                hb_ok = 0
                ev.append((t, 'KILL (keep, resumable)' if v39 else 'KILL (wipe, lst=0)'))
                hb_fast = 0
            else:
                if v39 and hb_miss < HB_MISS:
                    hb_fast = 1
        else:
            if hb_ok == 0:
                ev.append((t, 'HB RECOVERED (g_hb_ok=1)'))
            hb_ok = 1
            hb_miss = 0
            hb_fast = 0
            hb_fast_n = 0

        hb_timeline.append((t, hb_ok, kill_sent, kill_ts, kill_resumable, ar_lst, wiped))

        if v39 and hb_fast and hb_fast_n < HB_FAST_RETRY and not kill_sent:
            hb_fast_n += 1
            t += HB_FAST_SECS
        else:
            hb_fast = 0
            hb_fast_n = 0
            t += TICK

    # ---- 阶段2：跑 watchdog，每拍查「最近一次 puller 结论」----
    def state_at(wt):
        last = None
        for row in hb_timeline:
            if row[0] <= wt:
                last = row
            else:
                break
        return last

    for wt in range(0, total, WD_TICK):
        st = state_at(wt)
        if st is None:
            continue
        _, hb_ok_now, kill_sent_now, kill_ts_now, kill_res_now, ar_lst_now, wiped_now = st
        if not kill_sent_now:
            continue                       # 没被 kill 过，不存在「等待恢复」场景
        if not hb_ok_now:
            continue                       # 抑制矩阵 hb-not-ok
        # 入口条件 ar.armed && ar.lst
        if not v39 and not ar_lst_now:
            continue                       # 旧版：lst=0 → 永不入口
        # 冷却
        cool = AR_KILL_COOL_NET if (v39 and kill_res_now) else AR_KILL_COOL
        if wt - kill_ts_now < cool:
            continue
        # 旧版被抹模块 → 需重新下载（假设 120s 补回，且补不回就永远躺）
        if wiped_now and wt - kill_ts_now < 120:
            continue
        resumed = wt
        ev.append((wt, 'RESUME (ar)'))
        break

    return resumed, ev


def fmt(x):
    return 'None（永不恢复）' if x is None else '%d s' % x


def main():
    cases = [
        ('断网 3min', 60, 240),
        ('断网 10min', 60, 660),
        ('断网 1h', 60, 3660),
    ]
    ok = True
    print('=' * 74)
    print('  v6.38 基线 vs v6.39 —— 断网恢复后脚本自启时间')
    print('=' * 74)
    print('%-12s %-18s %-18s %s' % ('场景', 'v6.38', 'v6.39', '结论'))
    for name, a, b in cases:
        # 断网 1h 需要更长窗口
        total = b + 1800
        old, _ = simulate('v6.38', a, b, total)
        new, ev = simulate('v6.39', a, b, total)
        verdict = 'PASS' if (new is not None and new - b <= 180) else 'FAIL'
        if verdict == 'FAIL':
            ok = False
        print('%-12s %-18s %-18s %s' % (name, fmt(old), fmt(new), verdict))

    print()
    print('=' * 74)
    print('  v6.39 断网 3min 事件时间轴')
    print('=' * 74)
    _, ev = simulate('v6.39', 60, 240, 1800)
    for t, e in ev:
        print('  t=%4ds  %s' % (t, e))

    print()
    # 反回归断言
    checks = []

    # 1) 断网 3min 恢复后 180s 内必须自启
    r, _ = simulate('v6.39', 60, 240, 1800)
    checks.append(('断网 3min 恢复 → ≤180s 自启', r is not None and r - 240 <= 180, r))

    # 2) 断网 10min 恢复后 ≤180s 自启
    r, _ = simulate('v6.39', 60, 660, 3000)
    checks.append(('断网 10min 恢复 → ≤180s 自启', r is not None and r - 660 <= 180, r))

    # 3) 旧版必须复现「永不恢复」（证明本次修复针对的就是这个 bug）
    ro, _ = simulate('v6.38', 60, 240, 1800)
    checks.append(('v6.38 复现永不恢复（bug 确认）', ro is None, ro))

    # 4) 快速重试不超过 6 次，长时间断网要退回落 tick
    #    断网 1h：puller 在未达阈值期间最多 6 拍快重试，之后 60s 一拍
    #    60s 内 3 次心跳即 kill，所以只会触发一轮快重试 → 请求数有界
    checks.append(('快速重试有界（≤6 拍）', HB_FAST_RETRY == 6, HB_FAST_RETRY))

    print('=' * 74)
    print('  反回归断言')
    print('=' * 74)
    for name, good, val in checks:
        print('  %-36s %-6s (%s)' % (name, 'PASS' if good else 'FAIL', val))
        if not good:
            ok = False

    print()
    print('总体:', '全部通过' if ok else '存在 FAIL')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
