# -*- coding: utf-8 -*-
"""推送 CI 前的本地预检：
1) 从 build.yml 抽出所有 `strings bs_unlock.dylib | grep -q "XXX"` 断言，逐条在
   bs_unlock.m 里核对（缺失=CI 必挂）；
2) 抽出所有 FORBIDDEN 断言，检查是否仍然出现在源码里（出现=CI 必挂）；
3) 简单括号/花括号平衡检查。
注释里的字符串不会被编译进 .dylib，所以本脚本对"只在注释里出现"的情况会给出
WARN，需要人工确认那行是否真的在代码里。
"""
import os
import re
import sys

D = os.path.dirname(os.path.abspath(__file__))
yml = open(os.path.join(D, '.github', 'workflows', 'build.yml'), encoding='utf-8').read()
src = open(os.path.join(D, 'bs_unlock.m'), encoding='utf-8', errors='replace').read()
lines = src.split('\n')

# 去掉注释后的代码文本（粗略：// 行注释、/* */ 块注释）
code = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
code_nc = '\n'.join(re.sub(r'//.*$', '', ln) for ln in code.split('\n'))

pos = re.findall(r'grep -q "([^"]+)" \|\| \(echo "([^"]*)"', yml)
neg = re.findall(r'if strings bs_unlock\.dylib \| grep -q "([^"]+)"; then echo "([^"]*)"', yml)


def unesc(p):
    """grep BRE 转义 -> 源码里真实出现的字面量"""
    return p.replace('\\[', '[').replace('\\]', ']').replace('\\.', '.') \
            .replace('\\\\', '\\').replace('\\%', '%').replace('\\*', '*')


pos = [(unesc(p), m) for p, m in pos]
neg = [(unesc(p), m) for p, m in neg]

missing, warn, forbidden = [], [], []
for pat, msg in pos:
    if pat in code_nc:
        continue
    if pat in src:
        warn.append((pat, 'only in comment?'))
    else:
        missing.append((pat, msg))

for pat, msg in neg:
    if pat in code_nc:
        forbidden.append((pat, msg))

print('assertions(+)=%d  forbidden(-)=%d' % (len(pos), len(neg)))
print('MISSING=%d WARN=%d FORBIDDEN_HIT=%d' % (len(missing), len(warn), len(forbidden)))
for p, m in missing:
    print('  MISS %-52s | %s' % (p[:52], m[:40]))
for p, m in warn:
    print('  WARN %-52s | %s' % (p[:52], m[:40]))
for p, m in forbidden:
    print('  FORB %-52s | %s' % (p[:52], m[:40]))

# 括号平衡
for ch_o, ch_c in (('{', '}'), ('(', ')'), ('[', ']')):
    o, c = code_nc.count(ch_o), code_nc.count(ch_c)
    print('balance %s%s = %d/%d %s' % (ch_o, ch_c, o, c, 'OK' if o == c else 'MISMATCH'))

sys.exit(1 if (missing or forbidden) else 0)
