# -*- coding: utf-8 -*-
"""项目闸门判定表（复刻 bs_prj_guard_check 的版本族逻辑）。

目的：把「同项目不被误伤 / 越项目一定拦住」钉成断言，CI 跑。
逻辑必须与 bs_unlock.m 里 bs_prj_guard_check() 保持一致。
"""
import sys

PRJ_SJZ_VER_BASE = 0x030000
FAM_MASK = 0xFF0000


def guard(head_ver, prj, prj_ver=0):
    """返回 1 = 越项目（拦），0 = 放行。"""
    fam_want = 0
    have_fam = False
    if prj_ver:
        fam_want = prj_ver & FAM_MASK
        have_fam = True
    elif prj == 'sjz':
        fam_want = PRJ_SJZ_VER_BASE & FAM_MASK
        have_fam = True
    if not have_fam:
        return 0
    return 1 if (head_ver & FAM_MASK) != fam_want else 0


CASES = [
    # (说明, 包头版本, 卡密项目, 云端prj_ver, 期望)
    ('csws卡+csws包',        0x010803, 'csws', 0x010803, 0),
    ('csws卡+sjz包',         0x030107, 'csws', 0x010803, 1),   # ★ .109 事故形态
    ('csws卡+旧sjz包',       0x030104, 'csws', 0x010803, 1),
    ('sjz卡+sjz包',          0x030107, 'sjz',  0x030107, 0),
    ('sjz卡+sjz旧包',        0x030104, 'sjz',  0x030107, 0),   # 同族不同小版本：不误伤
    ('sjz卡+sjz更老包',      0x030000, 'sjz',  0x030107, 0),
    ('sjz卡+csws包',         0x010803, 'sjz',  0x030107, 1),
    ('无prj_ver csws卡+csws包', 0x010803, 'csws', 0, 0),       # 无法判定 -> 放行(不误伤)
    ('无prj_ver csws卡+sjz包',  0x030107, 'csws', 0, 0),       # 老云端兜不住 -> 靠服务端闸门
    ('无prj_ver sjz卡+sjz包',   0x030107, 'sjz',  0, 0),
    ('无prj_ver sjz卡+csws包',  0x010803, 'sjz',  0, 1),
]


def main():
    bad = 0
    for name, hv, prj, pv, exp in CASES:
        got = guard(hv, prj, pv)
        ok = (got == exp)
        if not ok:
            bad += 1
        print('%s %-26s head=%06x prj=%-5s prj_ver=%06x -> %d (want %d)'
              % ('OK  ' if ok else 'FAIL', name, hv, prj, pv, got, exp))
    print('---- %d/%d passed' % (len(CASES) - bad, len(CASES)))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
