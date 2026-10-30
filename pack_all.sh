#!/usr/bin/env bash
# =============================================================================
# pack_all.sh —— 通用打包 + 加密（不预设目录结构，全部内容原样进包）
#
# 三种输入：
#   1) 目录（如 androidfs/、system/、任意名字）→ 打包 → 加密
#   2) 目录 + --flat                            → 目录内容直接放 zip 根（不套顶层目录）
#   3) 单个文件（如 Superuser.apk）              → 不打包，直接整体加密
#
# 保真：符号链接用 -y 保留、权限与 setuid 一律不改、目录条目照原样
# 自检：打包前后对比 链接数 / setuid 数 / 条目数，可选 --ref 与原包逐条对比
#
# 用法：
#   ./pack_all.sh androidfs                       # -> androidfs.zip（顶层 androidfs/）
#   ./pack_all.sh ./内容目录 --flat                # -> 内容目录.zip（根下直接是文件）
#   ./pack_all.sh Superuser.apk                   # -> Superuser.apk.zip（apk 直接加密）
#   ./pack_all.sh androidfs -o 改好.zip --ref 原包.zip
#   ./pack_all.sh androidfs -n                    # 预检，只统计
#   ./pack_all.sh androidfs --no-encrypt          # 只打包不加密
# =============================================================================
set -uo pipefail

KEY_HEX="257a3839617669434d304b6b62457339"

die()  { printf '\033[31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[32m[信息]\033[0m %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[警告]\033[0m %s\n' "$*"; }
hdr()  { printf '\n\033[36m== %s ==\033[0m\n' "$*"; }

command -v zip     >/dev/null 2>&1 || die "需要 zip（apt install zip）"
command -v unzip   >/dev/null 2>&1 || die "需要 unzip"
command -v openssl >/dev/null 2>&1 || die "需要 openssl"

[ $# -ge 1 ] || { sed -n '9,21p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
SRC="${1%/}"; shift
[ -e "$SRC" ] || die "不存在：$SRC"

TOP=""; OUT=""; REF=""; DRY=0; ENC=1; FLAT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --as)         [ $# -ge 2 ] || die "--as 需要参数"; TOP="$2"; shift 2 ;;
    --flat)       FLAT=1; shift ;;
    -o)           [ $# -ge 2 ] || die "-o 需要参数"; OUT="$2"; shift 2 ;;
    --ref)        [ $# -ge 2 ] || die "--ref 需要参数"; REF="$2"; shift 2 ;;
    --no-encrypt) ENC=0; shift ;;
    -n)           DRY=1; shift ;;
    -h|--help)    sed -n '9,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)            die "未知参数：$1" ;;
  esac
done

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PLAIN="$WORK/plain.zip"
UID_NOW=$(id -u)
ZIPFLAGS="-r -y -q"
[ "$UID_NOW" -ne 0 ] && ZIPFLAGS="$ZIPFLAGS -X"

# =============================================================================
# A. 输入是单个文件：不打包，直接整体加密
# =============================================================================
if [ -f "$SRC" ]; then
  hdr "源文件"
  SZ=$(wc -c <"$SRC" | tr -d ' ')
  printf '  %s（%s 字节）\n' "$SRC" "$SZ"

  if [ "$(head -c 2 "$SRC")" = "PK" ]; then
    info "是明文（ZIP/APK 等 PK 开头的容器），将直接整体加密"
  else
    warn "开头不是 PK，可能已经是加密包或非 zip 格式"
  fi

  [ "$DRY" = "1" ] && { info "预检模式，不生成文件"; exit 0; }

  [ -n "$OUT" ] || OUT="$(pwd)/$(basename "$SRC").enc"
  if [ "$ENC" = "0" ]; then cp "$SRC" "$OUT"; info "未加密，输出：$OUT"; exit 0; fi

  hdr "加密"
  openssl enc -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$SRC" -out "$WORK/enc.bin" 2>/dev/null \
    || die "加密失败"
  ESZ=$(wc -c <"$WORK/enc.bin" | tr -d ' ')
  [ $((ESZ % 16)) -eq 0 ] || die "密文长度异常：$ESZ"
  cp "$WORK/enc.bin" "$OUT"
  printf '  %s -> %s（填充 %s 字节）\n' "$SZ" "$ESZ" "$((ESZ-SZ))"
  info "已输出：$OUT"

  hdr "回环校验"
  openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$OUT" -out "$WORK/back.bin" 2>/dev/null
  cmp -s "$WORK/back.bin" "$SRC" && ok "解密结果与原文件逐字节一致" || die "回环不一致"
  exit 0
fi

# =============================================================================
# B. 输入是目录
# =============================================================================
[ -d "$SRC" ] || die "既不是目录也不是文件：$SRC"

PARENT="$(cd "$(dirname "$SRC")" && pwd)"
BASE="$(basename "$SRC")"

# 顶层策略
if [ "$FLAT" = "1" ]; then
  MODE="flat"
elif [ "$BASE" = "androidfs" ] || [ "$BASE" = "system" ]; then
  MODE="wrap"; TOP="$BASE"
elif [ "$(find "$SRC" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" -eq 1 ] \
     && [ "$(find "$SRC" -mindepth 1 -maxdepth 1 -type f -name '*.apk' | wc -l | tr -d ' ')" -eq 1 ]; then
  MODE="flat"; warn "目录里只有一个 apk，按平铺打包（根下直接是 apk），保持与原包一致"
else
  MODE="wrap"; TOP="${TOP:-$BASE}"
  [ "$BASE" != "$TOP" ] && warn "包内顶层用 --as 指定为 $TOP/（源目录名 $BASE）"
fi

hdr "打包策略"
if [ "$MODE" = "flat" ]; then
  printf '  平铺：%s 下的内容直接进 zip 根\n' "$SRC"
else
  printf '  包裹：%s/ 作为 zip 顶层目录\n' "$TOP"
fi

hdr "预检"
NFILE=$(find "$SRC" -type f | wc -l | tr -d ' ')
NDIR=$(find "$SRC" -type d | wc -l | tr -d ' ')
NLINK=$(find "$SRC" -type l | wc -l | tr -d ' ')
NSUID=$(find "$SRC" -type f -perm -4000 | wc -l | tr -d ' ')
NSGID=$(find "$SRC" -type f -perm -2000 | wc -l | tr -d ' ')
NSPEC=$(find "$SRC" ! -type f ! -type d ! -type l | wc -l | tr -d ' ')
SIZE=$(du -sb "$SRC" 2>/dev/null | awk '{print $1}')
printf '  文件 %s，目录 %s，链接 %s，setuid %s，setgid %s，特殊 %s\n' "$NFILE" "$NDIR" "$NLINK" "$NSUID" "$NSGID" "$NSPEC"
printf '  总大小 %s 字节（约 %s MB）\n' "${SIZE:-0}" "$((${SIZE:-0}/1024/1024))"
[ "$NLINK" -gt 0 ] && ok "有 $NLINK 个符号链接，用 -y 保留为链接"
[ "$NSUID" -gt 0 ] && ok "有 $NSUID 个 setuid 文件，权限原样保留"
[ "$NSPEC" -gt 0 ] && warn "$NSPEC 个特殊文件（socket/fifo/设备节点）zip 存不了，会被跳过"
[ "${SIZE:-0}" -gt 4294967296 ] && { warn "超过 4GB，启用 zip64"; ZIPFLAGS="$ZIPFLAGS -fz"; }

if [ "$DRY" = "1" ]; then
  info "预检模式，不生成文件"
  exit 0
fi

# ---------- 打包 ----------
hdr "打包"
if [ "$MODE" = "flat" ]; then
  ( cd "$SRC" && find . -mindepth 1 -maxdepth 1 -print0 | xargs -0 zip $ZIPFLAGS "$PLAIN" ) \
    || die "打包失败"
else
  if [ "$BASE" = "$TOP" ]; then
    ( cd "$PARENT" && zip $ZIPFLAGS "$PLAIN" "$BASE" ) || die "打包失败"
  else
    mkdir -p "$WORK/stage"
    cp -a "$SRC" "$WORK/stage/$TOP" || die "复制到暂存目录失败"
    ( cd "$WORK/stage" && zip $ZIPFLAGS "$PLAIN" "$TOP" ) || die "打包失败"
  fi
fi

# ---------- 自检 ----------
hdr "打包结果自检"
[ -f "$PLAIN" ] || die "未生成 zip"
PSIZE=$(wc -c <"$PLAIN" | tr -d ' ')
PN=$(unzip -Z1 "$PLAIN" | wc -l | tr -d ' ')
PLINK=$(unzip -Z "$PLAIN" | awk 'NR>2 && $1 ~ /^l/' | wc -l | tr -d ' ')
PSUID=$(unzip -Z "$PLAIN" | awk 'NR>2 && $1 ~ /s/ || $1 ~ /S/' | wc -l | tr -d ' ')
printf '  %s 字节，%s 个条目\n' "$PSIZE" "$PN"

if [ "$MODE" = "wrap" ]; then
  [ "$PLINK" -eq "$NLINK" ] && ok "符号链接 $PLINK/$NLINK，全部保住" \
    || bad "符号链接不一致：源 $NLINK，zip 内 $PLINK（被展开了）"
  [ "$PSUID" -ge "$NSUID" ] && ok "setuid 保留（zip 内 $PSUID）" \
    || warn "setuid 不一致：源 $NSUID，zip 内 $PSUID"
fi
unzip -t -q "$PLAIN" >/dev/null 2>&1 && ok "ZIP 完整性通过" || bad "ZIP 校验失败"

TOPSET=$(unzip -Z1 "$PLAIN" | awk -F/ '{print $1}' | sort -u | head -5)
printf '  顶层：%s\n' "$(echo "$TOPSET" | tr '\n' ' ')"

# ---------- 与参考包对比 ----------
if [ -n "$REF" ]; then
  hdr "与原包对比"
  [ -f "$REF" ] || die "参考包不存在：$REF"
  if [ "$(head -c 2 "$REF")" = "PK" ]; then cp "$REF" "$WORK/ref.zip"
  else openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$REF" -out "$WORK/ref.zip" 2>/dev/null \
       || die "参考包解密失败"; fi

  listing() {
    unzip -Z "$1" | awk 'NR>2 && $1 ~ /^[-dl]/{n=$9; for(i=10;i<=NF;i++) n=n" "$i; printf "%s\t%s\t%s\n", $1, $4, n}' | sort -k3
  }
  listing "$WORK/ref.zip" >"$WORK/r.txt"
  listing "$PLAIN"       >"$WORK/p.txt"

  SAME=$(comm -12 <(cut -f3 "$WORK/r.txt" | sort) <(cut -f3 "$WORK/p.txt" | sort) | wc -l | tr -d ' ')
  ONLYR=$(comm -23 <(cut -f3 "$WORK/r.txt" | sort) <(cut -f3 "$WORK/p.txt" | sort))
  ONLYN=$(comm -13 <(cut -f3 "$WORK/r.txt" | sort) <(cut -f3 "$WORK/p.txt" | sort))
  printf '  条目名相同 %s 条\n' "$SAME"
  if [ -z "$ONLYR" ]; then ok "没有缺失条目"; else bad "缺少 $(echo "$ONLYR" | wc -l | tr -d ' ') 条："; echo "$ONLYR" | head -20 | sed 's/^/      /'; fi
  if [ -z "$ONLYN" ]; then ok "没有多余条目"; else warn "多出 $(echo "$ONLYN" | wc -l | tr -d ' ') 条："; echo "$ONLYN" | head -10 | sed 's/^/      /'; fi

  # 同名条目的权限差异
  join -t$'\t' -1 3 -2 3 <(sort -k3 "$WORK/r.txt") <(sort -k3 "$WORK/p.txt") 2>/dev/null \
    | awk -F'\t' '$2!=$4{print "      "$1"  "$2" -> "$4}' | head -15 >"$WORK/md.txt"
  if [ -s "$WORK/md.txt" ]; then bad "权限有差异："; cat "$WORK/md.txt"; else ok "同名条目权限一致"; fi
fi

# ---------- 加密 ----------
[ -n "$OUT" ] || OUT="$(pwd)/${TOP:-$BASE}.zip"
if [ "$ENC" = "0" ]; then
  cp "$PLAIN" "$OUT"; info "未加密，输出：$OUT"; exit 0
fi

hdr "加密"
openssl enc -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$PLAIN" -out "$WORK/enc.bin" 2>/dev/null \
  || die "加密失败"
ESIZE=$(wc -c <"$WORK/enc.bin" | tr -d ' ')
[ $((ESIZE % 16)) -eq 0 ] || die "密文长度不是 16 的倍数"
printf '  明文 %s -> 密文 %s（填充 %s 字节）\n' "$PSIZE" "$ESIZE" "$((ESIZE-PSIZE))"
mkdir -p "$(dirname "$OUT")"
cp "$WORK/enc.bin" "$OUT"
info "已输出：$OUT"

hdr "回环校验"
openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$OUT" -out "$WORK/back.zip" 2>/dev/null \
  || die "回环解密失败"
cmp -s "$WORK/back.zip" "$PLAIN" && ok "解密结果与打包明文逐字节一致" || die "回环不一致"
unzip -t -q "$WORK/back.zip" >/dev/null 2>&1 && ok "解密后 ZIP 可正常打开"

echo
info "完成"