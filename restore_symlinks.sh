#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#"""
#restore_symlinks —— 把被固化成普通文件的符号链接还原成链接

#症状：ROM 包里大量文件只有几字节到几十字节，内容是一段路径文本，例如
#    init              16 字节  ->  "/system/bin/init"
#    bin               11 字节  ->  "/system/bin"
#    system/bin/cat     6 字节  ->  "toybox"
#    system/bin/ueventd 4 字节  ->  "init"
#    结果 VM 启动时 exec 一个 16 字节的文本 -> ENOEXEC(8) -> get_elf_arch failed

#用法：
#    ./restore_symlinks.sh 坏包.zip --ref 原包.zip -- fix -o 修好.zip
#    ./restore_symlinks.sh 坏包.zip --auto -o 修好.zip       # 没有原包时按启发式判断
#    ./restore_symlinks.sh 坏包.zip --scan                   # 只报告，不修改
#    ./restore_symlinks.sh 坏包.zip --ref 原包.zip --no-perm -o 修好.zip   # 只修链接，不动权限

#默认 --fix：顺便把目录权限规范成 0755（缺 x 位会导致 App 报 "create dir ... failed"）。

import sys, os, io, zipfile, struct, subprocess, tempfile, shutil

KEY_HEX = "257a3839617669434d304b6b62457339"
S_IFMT, S_IFLNK, S_IFREG, S_IFDIR = 0o170000, 0o120000, 0o100000, 0o040000


def norm(path):
    """解密到临时 zip，返回 (路径, 临时目录)"""
    work = tempfile.mkdtemp()
    if open(path, "rb").read(2) == b"PK":
        return path, work
    out = os.path.join(work, "plain.zip")
    r = subprocess.run(["openssl", "enc", "-d", "-aes-128-ecb", "-nosalt",
                        "-K", KEY_HEX, "-in", path, "-out", out], capture_output=True)
    if r.returncode != 0 or open(out, "rb").read(2) != b"PK":
        raise SystemExit("解密失败：" + path)
    return out, work


def links_of(zip_path):
    """返回 {条目名: 链接目标}"""
    m = {}
    with zipfile.ZipFile(zip_path) as z:
        for i in z.infolist():
            if (i.external_attr >> 16) & S_IFMT == S_IFLNK:
                m[i.filename] = z.read(i).decode("utf-8", "replace")
    return m


def looks_like_link(name, data, names):
    """启发式：内容像路径，且目标在包内存在"""
    if not (0 < len(data) <= 512):
        return None
    try:
        t = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\n" in t or "\r" in t or "\x00" in t:
        return None
    t = t.strip()
    if not t or " " in t:
        return None
    # 目标存在性
    if t.startswith("/"):
        cand = t.lstrip("/")
        hit = any(n == cand or n.endswith("/" + cand) for n in names)
    else:
        base = name.rsplit("/", 1)[0] + "/" if "/" in name else ""
        cand = os.path.normpath(base + t)
        hit = cand in names and cand != name      # 不能指向自己
    if not hit:
        return None
    return t


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    src = sys.argv[1]
    ref = None; out = None; auto = False; scan = False; fixperm = True
    a = sys.argv[2:]
    i = 0
    while i < len(a):
        if a[i] == "--ref": ref = a[i+1]; i += 2
        elif a[i] == "--auto": auto = True; i += 1
        elif a[i] == "--scan": scan = True; i += 1
        elif a[i] == "--fix": fixperm = True; i += 1
        elif a[i] == "--no-perm": fixperm = False; i += 1
        elif a[i] == "-o": out = a[i+1]; i += 2
        else: raise SystemExit("未知参数：" + a[i])
    if not os.path.exists(src): raise SystemExit("文件不存在：" + src)

    plain, w1 = norm(src)
    linkmap = {}
    if ref:
        rp, w2 = norm(ref)
        linkmap = links_of(rp)
        print(f"参考包中符号链接：{len(linkmap)} 个")
    else:
        auto = True

    with zipfile.ZipFile(plain) as z:
        infos = z.infolist()
        names = {i.filename for i in infos}

        # 判定要修哪些
        todo = {}
        if ref:
            for i in infos:
                if i.filename in linkmap and (i.external_attr >> 16) & S_IFMT != S_IFLNK:
                    todo[i.filename] = linkmap[i.filename]
        else:
            for i in infos:
                if (i.external_attr >> 16) & S_IFMT == S_IFLNK:
                    continue
                if i.filename.endswith("/"):
                    continue
                data = z.read(i)
                t = looks_like_link(i.filename, data, names)
                if t:
                    todo[i.filename] = t

        print(f"待还原的条目：{len(todo)} 个")
        for n, t in list(todo.items())[:25]:
            print(f"    {n}  ->  {t}")
        if len(todo) > 25:
            print(f"    … 其余 {len(todo)-25} 个")

        if scan:
            print("\n（--scan 模式，未修改）")
            return
        if not todo:
            print("没有需要还原的条目"); return

        if not out:
            out = os.path.splitext(src)[0] + ".fixed.zip"
        tmp = out + ".part"
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zo:
            for i in infos:
                ni = zipfile.ZipInfo(i.filename, i.date_time)
                ni.create_system = 3
                ni.comment = i.comment
                if i.filename in todo:
                    ni.external_attr = (S_IFLNK | 0o777) << 16
                    ni.compress_type = zipfile.ZIP_STORED
                    zo.writestr(ni, todo[i.filename].encode())
                else:
                    m = i.external_attr >> 16
                    if fixperm and (i.filename.endswith("/") or (m & S_IFMT) == S_IFDIR):
                        # 目录一律 0755：缺 x 位会导致无法进入、mkdir 失败
                        ni.external_attr = ((S_IFDIR | 0o755) << 16) | 0x10
                    else:
                        ni.external_attr = i.external_attr
                    ni.compress_type = i.compress_type
                    with z.open(i) as fs, zo.open(ni, "w") as fd:
                        shutil.copyfileobj(fs, fd, 1024 * 1024)
        os.replace(tmp, out)
    print(f"已写出：{out}")

    if not out.endswith(".zip") or True:
        # 默认再加密一份，保持与原包一致
        enc = os.path.splitext(out)[0] + ".enc.zip"
        subprocess.run(["openssl", "enc", "-aes-128-ecb", "-nosalt", "-K", KEY_HEX,
                        "-in", out, "-out", enc], check=True)
        print(f"已加密：{enc}")


if __name__ == "__main__":
    main()