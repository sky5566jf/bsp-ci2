#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""断网恢复自启 —— 状态机仿真验证（不依赖真机）

v6.39 版：把「断网→kill→心跳恢复→[ar] 接上」抽成最小状态机。
   盲区：**没模拟 stall scan 的 disarm**。真机上 disarm 会把 ar.lst 清 0，
   入口条件直接不成立 —— 所以 v6.39 在本脚本里三场景全绿，真机却永久空闲。

v6.40 版：补上 disarm 这条链，并让 v6.39 在测试里**必须失败**（真机 bug 复现），
   v6.40 必须通过。断言分两组：
     A. 恢复能力：断网 3min/10min/1h 恢复后 ≤180s 自启
     B. 不误放行：用户真点停止、封禁类 kill、超出自我窗口 —— 三种情况都必须 still gate
"""
import sys

# ---------- 可调参数（与源码常量一致）----------
TICK = 60                 # g_tick（conf tick=60）
HB_MISS = 3               # conf hbmiss=3
HB_FAST_SECS = 20         # v6.39 新增
HB_FAST_RETRY = 6         # v6.39 新增
AR_KILL_COOL = 600        # 旧版：一律 600s
AR_KILL_COOL_NET = 90     # v6.39：网络类 90s
AR_KILL_SELF_WIN = 900    # v6.40：killswitch 自我认领窗口
WD_TICK = 5               # watchdog 扫描间隔（实测约 5s）
STALL_SCAN = 62           # [cr] stall scan 周期（60s）后第一拍


def stop_is_ours(kill_sent, kill_res, kill_ts, now):
    """★ v6.40 核心判据：这条 stop 是不是我们自己 killswitch 发的？

    对应源码 6055 / 6248 / 6285 三处的 `ours`/`kage` 判断。
    时间窗不可省 —— g_kill_resumable 置 1 后永不主动清零。
    """
    if not (kill_sent and kill_res and kill_ts):
        return False
    age = now - kill_ts
    return 0 <= age <= AR_KILL_SELF_WIN


def simulate(ver, offline_from, offline_to, total=1800, net_sig=True):
    """返回 (脚本恢复所需秒数 or None, 关键事件列表)

    net_sig=True  模拟真机形态：agent.log 里有 `tcp connect server timeout` /
                  `connect remote server3 failed` → v6.40 判 kind=6
    net_sig=False 模拟无网络签名的裸 stop（其他成因）→ v6.40 靠自我窗口认领
    """
    v39 = ver in ('v6.39', 'v6.40')
    v40 = (ver == 'v6.40')
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
    armed = 1
    disarmed = False
    resumed = None

    # ---- 阶段1：跑 puller，记录每次心跳结论的时间轴 ----
    hb_timeline = []          # [(时刻, hb_ok, kill_sent, kill_ts, kill_res, lst, wiped, armed)]
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

        # ---- ★ v6.40 新增：stall scan 的 disarm 判定（真机 13:46:28 那一步）----
        # kill 之后第一次扫描（STALL_SCAN 秒后）才会读到那条 `agent stop script`。
        # v6.39：兜底 kind=2 → 无条件清 lst/armed → 永久躺平（真机实测）。
        # v6.40：kind=6（有网络签名）或自我窗口认领 → 跳过 disarm。
        if kill_sent and not disarmed and t - kill_ts >= STALL_SCAN:
            disarmed = True
            if v39 and not v40:
                ar_lst = 0
                armed = 0
                ev.append((t, 'DISARM (kind=2 fallback) -> lst=0  ★v6.39 bug'))
            else:
                ours = stop_is_ours(kill_sent, kill_resumable, kill_ts, t)
                if net_sig:
                    ev.append((t, 'skip disarm (kind=6 network-fail sig)'))
                elif ours:
                    ev.append((t, 'skip disarm (our killswitch, %ds ago)' % (t - kill_ts)))
                else:
                    ar_lst = 0
                    armed = 0
                    ev.append((t, 'DISARM (not ours) -> lst=0'))

        hb_timeline.append((t, hb_ok, kill_sent, kill_ts, kill_resumable,
                            ar_lst, wiped, armed))
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
        _, hb_ok_now, kill_sent_now, kill_ts_now, kill_res_now, ar_lst_now, wiped_now, armed_now = st
        if not kill_sent_now:
            continue                       # 没被 kill 过，不存在「等待恢复」场景
        if not hb_ok_now:
            continue                       # 抑制矩阵 hb-not-ok
        # 入口条件 ar.armed && ar.lst
        if not (ar_lst_now and armed_now):
            continue                       # disarm 清过 → 永不入口（v6.39 真机死因）
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
    print('=' * 84)
    print('  断网恢复后脚本自启时间 —— v6.38 / v6.39（真机失败版）/ v6.40')
    print('=' * 84)
    print('%-12s %-18s %-22s %-16s %s' % ('场景', 'v6.38', 'v6.39（含 disarm）', 'v6.40', '结论'))
    for name, a, b in cases:
        total = b + 1800
        old, _ = simulate('v6.38', a, b, total)
        v39r, _ = simulate('v6.39', a, b, total)
        new, ev = simulate('v6.40', a, b, total)
        good = (new is not None and new - b <= 180 and v39r is None)
        verdict = 'PASS' if good else 'FAIL'
        if not good:
            ok = False
        print('%-12s %-18s %-22s %-16s %s'
              % (name, fmt(old), fmt(v39r), fmt(new), verdict))

    print()
    print('=' * 84)
    print('  v6.39 断网 3min 事件时间轴（真机 bug 复现）')
    print('=' * 84)
    _, ev = simulate('v6.39', 60, 240, 1800)
    for t, e in ev:
        print('  t=%4ds  %s' % (t, e))

    print()
    print('=' * 84)
    print('  v6.40 断网 3min 事件时间轴（有网络故障签名 → kind=6）')
    print('=' * 84)
    _, ev = simulate('v6.40', 60, 240, 1800, net_sig=True)
    for t, e in ev:
        print('  t=%4ds  %s' % (t, e))

    print()
    print('=' * 84)
    print('  v6.40 断网 3min 事件时间轴（无网络签名 → 自我窗口认领）')
    print('=' * 84)
    _, ev = simulate('v6.40', 60, 240, 1800, net_sig=False)
    for t, e in ev:
        print('  t=%4ds  %s' % (t, e))

    print()
    checks = []

    # ===== A 组：恢复能力 =====
    r, _ = simulate('v6.40', 60, 240, 1800, net_sig=True)
    checks.append(('A1 断网3min+网络签名 → ≤180s 自启', r is not None and r - 240 <= 180, r))

    r, _ = simulate('v6.40', 60, 240, 1800, net_sig=False)
    checks.append(('A2 断网3min+无签名 → ≤180s 自启', r is not None and r - 240 <= 180, r))

    r, _ = simulate('v6.40', 60, 660, 3000, net_sig=True)
    checks.append(('A3 断网10min → ≤180s 自启', r is not None and r - 660 <= 180, r))

    r, _ = simulate('v6.40', 60, 3660, 6000, net_sig=True)
    checks.append(('A4 断网1h → ≤180s 自启', r is not None and r - 3660 <= 180, r))

    # ===== B 组：v6.39 必须复现真机 bug（证明本次改的就是这条）=====
    ro, _ = simulate('v6.38', 60, 240, 1800)
    checks.append(('B1 v6.38 复现永不恢复', ro is None, ro))

    r39, _ = simulate('v6.39', 60, 240, 1800)
    checks.append(('B2 v6.39 复现永不恢复（disarm）', r39 is None, r39))

    # ===== C 组：不许误放行（防止修完变成「人停也拉」）=====
    checks.append(('C1 没 kill 过 → 人停必须 gate',
                   stop_is_ours(False, 1, 0, 1000) is False, None))
    checks.append(('C2 封禁类 kill(不可恢复) → 必须 gate',
                   stop_is_ours(True, 0, 1000, 1100) is False, None))
    checks.append(('C3 超出自我窗口(>900s) → 必须 gate',
                   stop_is_ours(True, 1, 1000, 1000 + AR_KILL_SELF_WIN + 1) is False, None))
    checks.append(('C4 窗口内自停 → 必须认领',
                   stop_is_ours(True, 1, 1000, 1000 + AR_KILL_SELF_WIN) is True, None))
    checks.append(('C5 快速重试有界（≤6 拍）', HB_FAST_RETRY == 6, HB_FAST_RETRY))

    print('=' * 84)
    print('  断言（A=恢复能力 / B=bug复现 / C=不许误放行）')
    print('=' * 84)
    for i, (name, good, val) in enumerate(checks, 1):
        print('  %-40s %-6s (%s)' % (name, 'PASS' if good else 'FAIL', val))
        if not good:
            ok = False

    print()
    print('总体:', '全部通过' if ok else '存在 FAIL')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
