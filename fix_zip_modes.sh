#!/usr/bin/env bash
# =============================================================================
# fix_zip_modes.sh —— 修复被压缩软件改坏的 zip：权限位 / 目录位 / 符号链接位
#
# 背景：Windows 上的 7-Zip / WinRAR / Bandizip 往 zip 里加文件时，新条目
#       external attributes 会被写成 0644 甚至 0，目录也会丢掉目录位。
#       App 解包时按这个权限 chmod，daemonsu 变 644 就再也起不来。
#
# 用法：
#   ./fix_zip_modes.sh 改坏的.zip                 # 按规则重设权限后重新加密
#   ./fix_zip_modes.sh 改坏的.zip --ref 原包.zip   # 按原包逐条对照（最准）
#   ./fix_zip_modes.sh 改坏的.zip -n              # 只报告不改
# =============================================================================
set -uo pipefail

KEY_HEX="257a3839617669434d304b6b62457339"

die()  { printf '\033[31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[32m[信息]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[警告]\033[0m %s\n' "$*"; }

command -v openssl >/dev/null 2>&1 || die "需要 openssl"
command -v python3 >/dev/null 2>&1 || die "需要 python3"

[ $# -ge 1 ] || { sed -n '11,16p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
PKG="$1"; shift
REF=""; OUT=""; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) [ $# -ge 2 ] || die "--ref 需要参数"; REF="$2"; shift 2 ;;
    -o)    [ $# -ge 2 ] || die "-o 需要参数"; OUT="$2"; shift 2 ;;
    -n)    DRY=1; shift ;;
    *)     die "未知参数：$1" ;;
  esac
done
[ -f "$PKG" ] || die "文件不存在：$PKG"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# 解密（如已加密）
if [ "$(head -c 2 "$PKG")" = "PK" ]; then
  cp "$PKG" "$WORK/in.zip"
else
  openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$PKG" -out "$WORK/in.zip" 2>/dev/null \
    || die "解密失败"
  [ "$(head -c 2 "$WORK/in.zip")" = "PK" ] || die "解密后不是 ZIP"
  info "已解密"
fi

if [ -n "$REF" ]; then
  if [ "$(head -c 2 "$REF")" = "PK" ]; then
    cp "$REF" "$WORK/ref.zip"
  else
    openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$REF" -out "$WORK/ref.zip" 2>/dev/null \
      || die "参考包解密失败"
  fi
fi

python3 - "$WORK/in.zip" "$WORK/out.zip" "${REF:+$WORK/ref.zip}" "$DRY" <<'PY'
import sys, zipfile

src, dst, ref, dry = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1"
EXEC_NAMES = {"daemonsu", "su", "init", "busybox", "toybox", "sh", "mksh"}
EXEC_DIRS  = ("/bin/", "/xbin/", "/sbin/", "/libexec/")

refmap = {}
if ref:
    with zipfile.ZipFile(ref) as zr:
        for i in zr.infolist():
            refmap[i.filename] = i.external_attr

S_IFMT  = 0o170000
S_IFDIR = 0o040000
S_IFLNK = 0o120000
S_IFREG = 0o100000

rows = []
zi = zipfile.ZipFile(src)
zo = None if dry else zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED)

for i in zi.infolist():
    data = zi.read(i.filename)
    mode = i.external_attr >> 16
    ftype = mode & S_IFMT
    isdir  = i.filename.endswith("/") or ftype == S_IFDIR
    islink = ftype == S_IFLNK

    old = "%s%04o" % ("l" if islink else ("d" if isdir else "-"), mode & 0o7777)

    if i.filename in refmap:
        new_attr = refmap[i.filename]
    elif islink:
        new_attr = (S_IFLNK | 0o777) << 16
    elif isdir:
        new_attr = ((S_IFDIR | 0o755) << 16) | 0x10
    else:
        base = i.filename.rsplit("/", 1)[-1]
        ex = (base in EXEC_NAMES or base.endswith(".sh")
              or any(d in i.filename for d in EXEC_DIRS))
        new_attr = (S_IFREG | (0o755 if ex else 0o644)) << 16

    nm = new_attr >> 16
    new = "%s%04o" % ("l" if (nm & S_IFMT) == S_IFLNK else ("d" if isdir else "-"), nm & 0o7777)

    if old != new:
        rows.append((i.filename, old, new))

    if zo:
        ni = zipfile.ZipInfo(i.filename, i.date_time)
        ni.compress_type = i.compress_type
        ni.create_system = 3          # 标记为 Unix，否则权限不被识别
        ni.external_attr = new_attr
        ni.comment = i.comment
        zo.writestr(ni, data)

if zo:
    zo.close()
zi.close()

print("  条目 %d 个，需要修正 %d 个" % (len(rows) + 0, len(rows)))
for n, o, w in rows[:40]:
    print("    %-58s %s -> %s" % (n[:58], o, w))
if len(rows) > 40:
    print("    ... 其余 %d 条省略" % (len(rows) - 40))
PY

if [ "$DRY" = "1" ]; then
  info "预演结束，未写出文件"
  exit 0
fi

unzip -t -q "$WORK/out.zip" >/dev/null 2>&1 || die "修复后 ZIP 校验失败"

[ -n "$OUT" ] || OUT="${PKG%.zip}.fixed.zip"
openssl enc -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$WORK/out.zip" -out "$OUT" 2>/dev/null \
  || die "加密失败"
info "已输出：$OUT（$(wc -c <"$OUT" | tr -d ' ') 字节）"

openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$OUT" -out "$WORK/back.zip" 2>/dev/null
cmp -s "$WORK/back.zip" "$WORK/out.zip" && info "回环校验通过" || die "回环校验失败"