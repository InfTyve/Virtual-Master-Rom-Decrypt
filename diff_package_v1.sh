#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
diff_package —— 逐条对比两个包，找出被修改/新增/删除的条目

用法：
    ./diff_package_v1.sh 原版.zip 改过.zip
    ./diff_package_v1.sh 原版.zip 改过.zip --full      # 显示全部差异，不截断
    ./diff_package_v1.sh 原版.zip 改过.zip --only-changed   # 只看内容变化的条目

支持加密包（自动用已知密钥解密）。对比维度：条目名、大小、CRC、类型、权限。
"""
import sys, os, zipfile, subprocess, tempfile

KEY_HEX = "257a3839617669434d304b6b62457339"
S_IFMT, S_IFLNK, S_IFDIR, S_IFREG = 0o170000, 0o120000, 0o040000, 0o100000


def norm(p, work, tag):
    if open(p, "rb").read(2) == b"PK":
        return p
    out = os.path.join(work, tag + ".zip")
    r = subprocess.run(["openssl", "enc", "-d", "-aes-128-ecb", "-nosalt",
                        "-K", KEY_HEX, "-in", p, "-out", out], capture_output=True)
    if r.returncode != 0 or open(out, "rb").read(2) != b"PK":
        raise SystemExit("解密失败：" + p)
    return out


def index(zp):
    d = {}
    with zipfile.ZipFile(zp) as z:
        for i in z.infolist():
            m = i.external_attr >> 16
            d[i.filename] = {
                "size": i.file_size,
                "csize": i.compress_size,
                "crc": i.CRC,
                "mode": m,
                "type": "link" if (m & S_IFMT) == S_IFLNK else
                        ("dir" if i.filename.endswith("/") or (m & S_IFMT) == S_IFDIR else "file"),
                "method": i.compress_type,
            }
    return d


def perm(m):
    t = m & S_IFMT
    p = m & 0o7777
    s = ("l" if t == S_IFLNK else "d" if t == S_IFDIR else "-")
    bits = "rwxrwxrwx"
    out = ""
    for k in range(9):
        out += bits[k] if p & (1 << (8 - k)) else "-"
    return s + out


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    a, b = sys.argv[1], sys.argv[2]
    full = "--full" in sys.argv
    only_changed = "--only-changed" in sys.argv
    if not (os.path.exists(a) and os.path.exists(b)):
        raise SystemExit("文件不存在")

    work = tempfile.mkdtemp()
    pa = norm(a, work, "a"); pb = norm(b, work, "b")
    A = index(pa); B = index(pb)

    only_a = [k for k in A if k not in B]
    only_b = [k for k in B if k not in A]
    both = [k for k in A if k in B]

    changed, perm_changed, type_changed = [], [], []
    for k in both:
        x, y = A[k], B[k]
        if x["type"] != y["type"]:
            type_changed.append(k)
        elif x["crc"] != y["crc"] or x["size"] != y["size"]:
            changed.append(k)
        elif x["mode"] != y["mode"]:
            perm_changed.append(k)

    print(f"\n原包：{a}   条目 {len(A)}")
    print(f"新包：{b}   条目 {len(B)}")

    def show(title, items, detail=None, limit=None):
        print(f"\n== {title}：{len(items)} ==")
        rows = items if (full or not limit) else items[:limit]
        for k in rows:
            line = f"  {k}"
            if detail:
                line += "   " + detail(k)
            print(line)
        if len(items) > len(rows):
            print(f"  … 其余 {len(items)-len(rows)} 条（--full 显示全部）")

    if not only_changed:
        show("仅原包有（删除/丢失）", only_a, lambda k: f"[{A[k]['type']} {perm(A[k]['mode'])} {A[k]['size']}B]", 30)
        show("仅新包有（新增）", only_b, lambda k: f"[{B[k]['type']} {perm(B[k]['mode'])} {B[k]['size']}B]", 30)

    def det_changed(k):
        x, y = A[k], B[k]
        s = f"{x['size']}B"
        if x["size"] != y["size"]:
            s += f" -> {y['size']}B"
        return s + f"  crc {x['crc']:08x}->{y['crc']:08x}"

    def det_perm(k):
        return f"{perm(A[k]['mode'])} -> {perm(B[k]['mode'])}"

    show("内容被修改", changed, det_changed, 40)
    show("类型改变（文件/目录/链接）", type_changed, lambda k: f"{A[k]['type']} -> {B[k]['type']}", 40)
    show("仅权限变化", perm_changed, det_perm, 20)

    print("\n== 摘要 ==")
    print(f"  删除 {len(only_a)}   新增 {len(only_b)}   内容改动 {len(changed)}   "
          f"类型改动 {len(type_changed)}   权限改动 {len(perm_changed)}")

    # 高亮关键路径
    KEY = ("build.prop", "/bin/init", "libhidl", "composer", "manifest.xml",
           "framework.jar", "sepolicy", "vendor/lib64/hw", "libc.so", "libm.so")
    hits = [k for k in (changed + type_changed + only_a + only_b) if any(s in k for s in KEY)]
    if hits:
        print("\n== 关键文件变动（值得重点看）==")
        for k in hits[:20]:
            print(f"  {k}")


if __name__ == "__main__":
    main()