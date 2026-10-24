#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析天翼校园客户端 Web UI 的 !#CWERD# 加密容器（numpy 版）。

判据：
  1) 头 8 字节 == b'!#CWERD#'，其余为密文；
  2) 密文长度 = 明文长度（无分组填充）→ 不是带填充的分组密码；
  3) 重复密钥 XOR：c[i]==c[i+p] 命中率 / 每列最大频率 在真实周期处出尖峰；
  4) 固定密钥流（无周期）：不同文件在同一偏移共享密钥流 → 可用开源库做 crib。

用法:
  python tools\\Analyze-CweContainer.py scan                 # 概览 + 周期扫描
  python tools\\Analyze-CweContainer.py crib --crib <明文> --target <CWERD> --out <key>
"""
import argparse
import os
import sys
from collections import Counter
import math

import numpy as np

MAGIC = b'!#CWERD#'
CLIENT_DIR = r'D:\tools\Chinatelecom_JSPortal'


def read_container(path):
    with open(path, 'rb') as f:
        raw = f.read()
    if raw[:8] != MAGIC:
        raise ValueError('not a CWERD container: %s' % path)
    return raw, raw[8:]


def entropy(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def period_metrics(ct, max_period=4096, sample=150000):
    arr = np.frombuffer(ct[:sample], dtype=np.uint8)
    n = arr.size
    hits, icoc = [], []
    for p in range(1, min(max_period, n - 1) + 1):
        m = n - p
        a, b = arr[:m], arr[p:p + m]
        hits.append((p, float(np.count_nonzero(a == b)) / m))
        # 每列最大频率的平均值（列 = 同余位置）
        col = arr[: (n // p) * p].reshape(-1, p)
        freq = np.array([np.bincount(col[:, j], minlength=256).max() for j in range(p)])
        icoc.append((p, float(freq.mean()) / col.shape[0]))
    return hits, icoc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', nargs='?', default='scan', choices=['scan', 'crib'])
    ap.add_argument('--crib')
    ap.add_argument('--target')
    ap.add_argument('--out')
    ap.add_argument('--max-period', type=int, default=4096)
    args = ap.parse_args()

    if args.mode == 'crib':
        with open(args.crib, 'rb') as f:
            pt = f.read()
        _, ct = read_container(args.target)
        n = min(len(pt), len(ct))
        ks = np.bitwise_xor(np.frombuffer(pt[:n], np.uint8), np.frombuffer(ct[:n], np.uint8))
        print('crib=%d 密文=%d 对齐后=%d' % (len(pt), len(ct), n))
        base = os.path.dirname(os.path.abspath(args.target))
        for probe in ['dialMgr.js', 'cwe-core.js', 'globalDefine.js', 'aes_1.js']:
            pp = os.path.join(base, probe)
            if not os.path.exists(pp):
                continue
            _, pc = read_container(pp)
            m = min(n, len(pc))
            dec = np.bitwise_xor(ks[:m], np.frombuffer(pc[:m], np.uint8)).tobytes()
            head = dec[:200]
            ok = sum(1 for x in head if 32 <= x < 127 or x in (9, 10, 13))
            print('  [自检] %-16s 可打印率=%.2f  %r' % (probe, ok / max(1, len(head)), dec[:70]))
        with open(args.out, 'wb') as f:
            f.write(ks.tobytes())
        print('密钥流 -> %s' % args.out)
        return 0

    js_dir = os.path.join(CLIENT_DIR, 'view', 'js')
    files = sorted(f for f in os.listdir(js_dir) if f.endswith('.js'))
    print('=== view\\js 容器概览 ===')
    print('%-30s %8s %8s %8s' % ('file', 'size', 'ct_len', 'entropy'))
    for fn in files:
        raw, ct = read_container(os.path.join(js_dir, fn))
        print('%-30s %8d %8d %8.3f' % (fn, len(raw), len(ct), entropy(ct)))

    big = os.path.join(js_dir, 'mootools-core-1.4-full.js')
    _, ct = read_container(big)
    print('\n=== 周期扫描: mootools-core-1.4-full.js (密文 %d 字节) ===' % len(ct))
    hits, icoc = period_metrics(ct, args.max_period)
    print('-- c[i]==c[i+p] 命中率 top10 --')
    for p, v in sorted(hits, key=lambda x: -x[1])[:10]:
        print('   p=%-6d %.5f' % (p, v))
    print('-- 每列最大频率 top10 --')
    for p, v in sorted(icoc, key=lambda x: -x[1])[:10]:
        print('   p=%-6d %.5f' % (p, v))
    print('-- 小周期明细 (1..32) --')
    d_hits = dict(hits)
    d_ic = dict(icoc)
    for p in range(1, 33):
        print('   p=%-3d hits=%.5f  icoc=%.5f' % (p, d_hits.get(p, 0), d_ic.get(p, 0)))
    return 0


if __name__ == '__main__':
    sys.exit(main())