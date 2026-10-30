#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zip_doctor —— ZIP 结构体检：EOCD / 中央目录 / 条目偏移一致性

专门用于定位这类报错：
    java.io.IOException: data for xxx/ overlaps with central directory
    java.io.IOException: Error on ZipFile unknown archive

用法：
    ./zip_doctor.sh 文件              # 明文 zip 或加密包都行
    ./zip_doctor.sh 文件 --deep       # 额外校验每个条目的本地头签名（慢，大包慎用）

判断依据：
    - EOCD 记录的“中央目录偏移”与真实位置是否一致
    - 每个条目的数据区是否越过中央目录起点
    - 是否存在 zip64 结构、末尾多余字节、多份 EOCD
"""
import sys, os, struct, subprocess, tempfile

KEY_HEX = "257a3839617669434d304b6b62457339"
EOCD = b"PK\x05\x06"
Z64_EOCD = b"PK\x06\x06"
Z64_LOC = b"PK\x06\x07"
CDH = b"PK\x01\x02"
LFH = b"PK\x03\x04"

OK, BAD, INFO = "  \033[32m✓\033[0m", "  \033[31m✗\033[0m", "  \033[33m!\033[0m"


def find_eocd(fp, size):
    """从尾部向前找 EOCD，返回 (pos, 所有候选位置)"""
    back = min(size, 65557 + 64)
    fp.seek(size - back)
    buf = fp.read(back)
    hits = []
    i = len(buf)
    while True:
        i = buf.rfind(EOCD, 0, i)
        if i < 0:
            break
        if i + 22 <= len(buf):
            # 校验注释长度是否正好到文件尾
            clen = struct.unpack_from("<H", buf, i + 20)[0]
            hits.append((size - back + i, i + 22 + clen == len(buf)))
        i -= 1
    if not hits:
        return None, []
    exact = [h for h in hits if h[1]]
    return (exact[0] if exact else hits[0])[0], hits


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    deep = "--deep" in sys.argv
    if not os.path.exists(path):
        print("文件不存在:", path); sys.exit(1)

    work = tempfile.mkdtemp()
    target = path
    if open(path, "rb").read(2) != b"PK":
        print("开头不是 PK，尝试用已知密钥解密…")
        out = os.path.join(work, "d.zip")
        r = subprocess.run(["openssl", "enc", "-d", "-aes-128-ecb", "-nosalt",
                            "-K", KEY_HEX, "-in", path, "-out", out],
                           capture_output=True)
        if r.returncode == 0 and open(out, "rb").read(2) == b"PK":
            print("  ✓ 解密成功（AES-128-ECB）")
            target = out
        else:
            print("  ! 无法解密，按原始字节直接分析结构（可能是头部有垃圾或偏移错位）")

    size = os.path.getsize(target)
    print("\n== 基本信息 ==")
    print(f"  文件：{path}")
    print(f"  明文大小：{size:,} 字节（{size/1024/1024:.2f} MB）")
    print(f"  16 对齐：{'是' if size % 16 == 0 else '否'}")

    fp = open(target, "rb")
    eocd, hits = find_eocd(fp, size)
    print("\n== EOCD ==")
    if eocd is None:
        print(f"{BAD} 找不到 EOCD，文件不完整或已被截断")
        fp.close(); sys.exit(3)
    print(f"  EOCD 位置：{eocd:,}（文件尾偏移 {size-eocd} 字节）")
    if len(hits) > 1:
        print(f"{BAD} 找到 {len(hits)} 个 EOCD 候选位置：{[h[0] for h in hits[:5]]}")
        print("     多个 EOCD 通常意味着文件被拼接或二次封装")
    else:
        print(f"{OK} EOCD 唯一")

    fp.seek(eocd)
    raw = fp.read(22)
    _, _, _, _, n_this, cd_size, cd_off, clen = struct.unpack("<4sHHHHIIH", raw)
    print(f"  条目数：{n_this}   中央目录大小：{cd_size:,}   中央目录偏移：{cd_off:,}")
    print(f"  注释长度：{clen}")

    # zip64
    has64 = False
    if eocd >= 20:
        fp.seek(eocd - 20); loc = fp.read(4)
        if loc == Z64_LOC:
            has64 = True
            fp.seek(eocd - 20 + 8)
            z64off = struct.unpack("<Q", fp.read(8))[0]
            print(f"\n== ZIP64 ==")
            print(f"  发现 zip64 EOCD locator，指向 {z64off:,}")
            fp.seek(z64off); sig = fp.read(4)
            if sig == Z64_EOCD:
                d = fp.read(56)
                (_, _, _, _, _, n64, cds64, cdo64) = struct.unpack("<4sQHHIIQQ", sig + d[:52])
                print(f"  zip64 EOCD：条目 {n64}，CD 大小 {cds64:,}，CD 偏移 {cdo64:,}")
                if cdo64 != cd_off and cd_off != 0xFFFFFFFF:
                    print(f"{BAD} zip64 与普通 EOCD 记录的 CD 偏移不一致")
            else:
                print(f"{BAD} locator 指向的位置不是 zip64 EOCD 签名")

    # 真实 CD 位置反推：CD 应紧邻 EOCD（或 zip64 EOCD）之前
    real_cd_end = eocd - (76 if has64 else 0)
    real_cd_start = real_cd_end - cd_size
    print("\n== 中央目录定位 ==")
    if real_cd_start < 0:
        print(f"{BAD} 推算出的 CD 起点为负，记录值不可信")
    else:
        fp.seek(real_cd_start); sig = fp.read(4)
        if sig == CDH:
            print(f"{OK} 按“CD 紧邻 EOCD”反推，CD 起点 {real_cd_start:,} 处是合法签名")
            if real_cd_start != cd_off:
                print(f"{BAD} 但 EOCD 记录的偏移是 {cd_off:,}，相差 {real_cd_start-cd_off:+,} 字节")
                print("     → 偏移错位，这正是 overlaps 报错的直接原因")
            else:
                print(f"{OK} 与 EOCD 记录一致")
        else:
            print(f"{BAD} {real_cd_start:,} 处不是中央目录签名（读到 {sig.hex()}）")
            print("     → 文件很可能被截断，或尾部被追加了数据")

    # 逐条读 CD
    print("\n== 条目检查 ==")
    pos = real_cd_start
    entries = []
    bad = 0
    for i in range(min(n_this, 200000)):
        fp.seek(pos); h = fp.read(46)
        if len(h) < 46 or h[:4] != CDH:
            print(f"{BAD} 第 {i+1} 条中央目录记录损坏（pos={pos:,}，签名 {h[:4].hex()}）")
            bad += 1
            break
        (_, _, _, _, method, _, _, crc, csize, usize, nlen, elen, clen2,
         _, _, _, lho) = struct.unpack("<4sHHHHHHIIIHHHHHII", h)
        name = fp.read(nlen).decode("utf-8", "replace")
        extra = fp.read(elen); fp.read(clen2)

        # zip64 extra
        if 0xFFFFFFFF in (csize, usize, lho) or (usize == 0xFFFFFFFF):
            k = 0
            while k + 4 <= len(extra):
                hid, hsz = struct.unpack_from("<HH", extra, k)
                if hid == 0x0001:
                    v = extra[k+4:k+4+hsz]
                    p = 0
                    if usize == 0xFFFFFFFF and p+8 <= len(v): usize = struct.unpack_from("<Q", v, p)[0]; p += 8
                    if csize == 0xFFFFFFFF and p+8 <= len(v): csize = struct.unpack_from("<Q", v, p)[0]; p += 8
                    if lho == 0xFFFFFFFF and p+8 <= len(v): lho = struct.unpack_from("<Q", v, p)[0]; p += 8
                k += 4 + hsz

        entries.append((name, lho, csize, usize, method))
        data_end = lho + 30 + nlen + elen + csize
        flag = ""
        if data_end > real_cd_start:
            flag = "  <== 数据区越过中央目录"
            bad += 1
        if lho >= size:
            flag += "  <== 偏移超出文件"
            bad += 1
        if flag:
            print(f"{BAD} {name}  offset={lho:,} csize={csize:,} data_end={data_end:,}{flag}")
        if deep and i < 5000:
            fp.seek(lho)
            if fp.read(4) != LFH:
                print(f"{BAD} {name} 的本地头签名不对（offset={lho:,}）")
                bad += 1
        pos += 46 + nlen + elen + clen2

    # 按 offset 排序看是否重叠
    entries.sort(key=lambda x: x[1])
    overlap = 0
    for i in range(1, len(entries)):
        prev_end = entries[i-1][1] + entries[i-1][2]
        if entries[i][1] < prev_end:
            overlap += 1
            if overlap <= 5:
                print(f"{BAD} {entries[i][0]} 与前一条数据重叠（{entries[i][1]:,} < {prev_end:,}）")

    print(f"\n  共解析 {len(entries)} 条，异常 {bad} 处，条目间重叠 {overlap} 处")
    if bad == 0 and overlap == 0 and real_cd_start == cd_off:
        print(f"{OK} 结构自洽，commons-compress 不应报 overlaps")
    elif bad == 0 and overlap == 0:
        print(f"{INFO} 条目自身自洽，但整体偏移错了 {real_cd_start-cd_off:+,} 字节")

    # 末尾多余字节
    tail_extra = size - eocd - 22 - clen
    if tail_extra != 0:
        print(f"{INFO} EOCD 之后还有 {tail_extra:,} 字节（加密填充或垃圾）")
    fp.close()

    print("\n== 结论 ==")
    if real_cd_start >= 0 and real_cd_start != cd_off:
        print("  中央目录偏移与真实位置不符 → 打包/加密环节在文件头部或中段改变了长度")
        print("  例如：加密时在开头加了 IV/salt 头，解密端未跳过，导致整体错位")
    elif bad or overlap:
        print("  文件已损坏或被截断，无法直接修复，建议用原始包重做")
    else:
        print("  结构看起来正常；若 App 仍报错，请检查是否解出了完整的 zip（末尾填充是否被截掉）")


if __name__ == "__main__":
    main()