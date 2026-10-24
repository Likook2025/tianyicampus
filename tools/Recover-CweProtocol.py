#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CWERD 容器密钥流恢复（EM 迭代版）。

原理
----
已证实：所有 !#CWERD# 容器共享同一条全局密钥流 K（无 per-file IV）。
偏移 i 处有多个观测 c_j = K_i ^ p_j，明文 p_j 服从"JS 源码字节分布" D。
  逐偏移 argmax_k  sum_j log D(c_j ^ k)  →  K_i
再用第一轮解出的文本重新估计 D（EM），迭代提升精度。

用法:
  python tools\\Recover-CweProtocol.py --max-offset 6000 --em 5 --dump
"""
import argparse
import os
import sys
from collections import Counter

import numpy as np

MAGIC = b'!#CWERD#'
CLIENT = r'D:\tools\Chinatelecom_JSPortal'
JS_DIR = os.path.join(CLIENT, 'view', 'js')
OUT_DIR = r'D:\Codex\tianyicampus'

# 关注的文件（协议 / 凭据 / 桥接相关）
INTEREST = ['dialMgr.js', 'globalDefine.js', 'cwe-core.js', 'FunInterface.js',
            'funCtrl.js', 'main.js', 'util.js', 'infoCenter.js', 'edit-core.js',
            'aes_1.js', 'app.js', 'menu.js', 'msgbox.js']


def load(path):
    raw = open(path, 'rb').read()
    assert raw[:8] == MAGIC, path
    return raw[8:]


def prior_from_dir():
    """用客户端目录里所有明文 JS/CSS/HTML 估计字节分布。"""
    cnt = Counter()
    for root, _, names in os.walk(CLIENT):
        for n in names:
            if not n.lower().endswith(('.js', '.css', '.html', '.htm', '.xml', '.json', '.ini')):
                continue
            p = os.path.join(root, n)
            try:
                b = open(p, 'rb').read()
            except OSError:
                continue
            if b[:8] == MAGIC:
                continue          # 加密的不算
            cnt.update(b)
    total = sum(cnt.values())
    p = np.full(256, 1.0 / (total + 256.0))
    for byte, c in cnt.items():
        p[byte] = (c + 1.0) / (total + 256.0)
    for byte in range(128, 256):       # 源码里几乎不出现高位字节
        p[byte] = 1e-7
    p /= p.sum()
    return np.log(p), total


def recover(cts, logp, offsets):
    K = np.zeros(offsets, dtype=np.uint8)
    conf = np.zeros(offsets, dtype=np.float64)
    for i in range(offsets):
        cb = np.array([v[i] for v in cts if len(v) > i], dtype=np.uint8)
        if cb.size == 0:
            break
        idx = cb[None, :] ^ np.arange(256, dtype=np.uint8)[:, None]
        sc = logp[idx].sum(axis=1)
        o = np.argsort(sc)
        K[i] = o[-1]
        conf[i] = sc[o[-1]] - sc[o[-2]]
    return K, conf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-offset', type=int, default=6000)
    ap.add_argument('--em', type=int, default=5)
    ap.add_argument('--dump', action='store_true')
    args = ap.parse_args()

    names = sorted(f for f in os.listdir(JS_DIR) if f.endswith('.js'))
    cts = [load(os.path.join(JS_DIR, f)) for f in names]
    maxlen = max(len(v) for v in cts)
    offsets = min(args.max_offset, maxlen)

    logp, n_prior = prior_from_dir()
    print('先验语料 %d 字节；文件 %d 个；恢复 %d 个偏移' % (n_prior, len(names), offsets))

    K = conf = None
    for it in range(args.em):
        K, conf = recover(cts, logp, offsets)
        # 用本轮解出的文本重建 D
        pooled = Counter()
        for v in cts:
            m = min(offsets, len(v))
            pt = np.bitwise_xor(np.frombuffer(v[:m], np.uint8), K[:m])
            pooled.update(pt.tobytes())
        total = sum(pooled.values())
        p = np.full(256, 1.0 / (total + 256.0))
        for b, c in pooled.items():
            p[b] = (c + 1.0) / (total + 256.0)
        for b in range(128, 256):
            p[b] = 1e-7
        p /= p.sum()
        logp = np.log(p)
        med = np.median(conf)
        print('  EM 第 %d 轮：可信度中位数 %.2f，第10百分位 %.2f' % (it + 1, med, np.percentile(conf, 10)))

    # 每个偏移的样本数（决定可靠性）
    counts = np.zeros(offsets, dtype=np.int32)
    for v in cts:
        counts[:min(offsets, len(v))] += 1

    lines = []
    for f, v in zip(names, cts):
        m = min(offsets, len(v))
        pt = np.bitwise_xor(np.frombuffer(v[:m], np.uint8), K[:m]).tobytes()
        lowconf = int((conf[:m] < 1.0).sum())
        lines.append('=' * 78)
        lines.append('%s   解出 %d/%d 字节   低可信偏移 %d 个   偏移末端样本数 %d'
                     % (f, m, len(v), lowconf, counts[m - 1] if m else 0))
        lines.append('=' * 78)
        lines.append(''.join(chr(c) if (32 <= c < 127 or c in (9, 10, 13)) else '.' for c in pt))

    report = os.path.join(OUT_DIR, 'cwe-decrypted-all.txt')
    with open(report, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines))
    print('全部明文 -> %s' % report)

    if args.dump:
        for target in INTEREST:
            if target not in names:
                continue
            v = cts[names.index(target)]
            m = min(offsets, len(v))
            pt = np.bitwise_xor(np.frombuffer(v[:m], np.uint8), K[:m]).tobytes()
            out = os.path.join(OUT_DIR, 'cwe-dec-%s.txt' % target.replace('.js', ''))
            with open(out, 'w', encoding='utf-8') as fh:
                fh.write(''.join(chr(c) if (32 <= c < 127 or c in (9, 10, 13)) else '.' for c in pt))
            print('  -> %s' % out)
    return 0


if __name__ == '__main__':
    sys.exit(main())