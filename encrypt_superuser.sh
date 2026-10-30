#!/usr/bin/env bash
# =============================================================================
# encrypt_superuser.sh —— 重新打包并加密 Superuser 镜像包（与 App 端算法/密钥一致）
#
# 算法来源：com.android.vmcore.installer.ImageInstallerV1
#   Cipher.getInstance("AES")                    -> AES/ECB/PKCS5Padding
#   SecretKeySpec("%z89aviCM0KkbEs9".getBytes(), "AES")
#   整个 zip 作为单一流加密（不是逐文件加密），输出无任何文件头
#
# 用法：
#   ./encrypt_superuser.sh superuser/                 # 目录 -> 打包 -> 加密为 superuser.zip
#   ./encrypt_superuser.sh 改好的.zip                 # 明文 zip -> 直接加密为 改好的.enc.zip
#   ./encrypt_superuser.sh superuser/ -o superuser.zip
#   ./encrypt_superuser.sh superuser/ -k              # 保留中间明文 zip 便于排查
# =============================================================================
set -euo pipefail

KEY_HEX="257a3839617669434d304b6b62457339"   # "%z89aviCM0KkbEs9" 的十六进制
KEY_RAW='%z89aviCM0KkbEs9'

die()  { printf '\033[31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[32m[信息]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[警告]\033[0m %s\n' "$*"; }
usage(){ sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

OUT=""
KEEP=0
FIXPERM=1

if [ $# -eq 0 ]; then usage; fi
SRC=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output)  [ $# -ge 2 ] || die "-o 需要一个参数"; OUT="$2"; shift 2 ;;
    -k|--keep)    KEEP=1; shift ;;
    --no-fix-perm) FIXPERM=0; shift ;;
    -h|--help)    usage ;;
    -*)           die "未知选项：$1" ;;
    *)            [ -z "$SRC" ] || die "一次只能处理一个输入"; SRC="$1"; shift ;;
  esac
done
[ -n "$SRC" ] || usage
[ -e "$SRC" ] || die "输入不存在：$SRC"

command -v openssl >/dev/null 2>&1 || die "未找到 openssl"
command -v unzip   >/dev/null 2>&1 || die "未找到 unzip"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PLAIN="$WORK/plain.zip"
TMPOUT="$WORK/enc.tmp"

# ---------- 1. 准备明文 zip ----------
if [ -d "$SRC" ]; then
  command -v zip >/dev/null 2>&1 || die "未找到 zip，无法打包目录"
  SRC="${SRC%/}"

  # 定位包含 system/ 的那一层，避免 zip 里多出一级目录
  if [ -d "$SRC/system" ]; then
    ROOT="$SRC"
  elif [ "$(basename "$SRC")" = "system" ]; then
    ROOT="$(dirname "$SRC")"
  else
    die "目录里找不到 system/ 子目录，拒绝打包（App 要求镜像内路径为 system/...）"
  fi

  # 拷贝一份再改权限，绝不动用户原始文件
  mkdir -p "$WORK/stage"
  cp -a "$ROOT/system" "$WORK/stage/" 2>/dev/null || cp -R "$ROOT/system" "$WORK/stage/"

  if [ "$FIXPERM" -eq 1 ]; then
    # 目录 755；二进制与脚本 755；其余 644 —— 否则装进 /system 后 su 起不来
    find "$WORK/stage" -type d -exec chmod 755 {} +
    find "$WORK/stage" -type f -exec chmod 644 {} +
    find "$WORK/stage" -type f \( -name 'daemonsu' -o -name 'su' -o -name '*.sh' \) -exec chmod 755 {} +
    info "已规范化权限：目录 755、daemonsu 755、其余文件 644"
  fi

  info "打包目录：$ROOT/system"
  ( cd "$WORK/stage" && zip -r -X -q "$PLAIN" system )
else
  case "$SRC" in
    *.zip) ;;
    *) die "输入既不是目录也不是 .zip" ;;
  esac
  if [ "$(head -c 2 "$SRC")" != "PK" ]; then
    die "$SRC 不是明文 ZIP（可能已经加密过）"
  fi
  cp "$SRC" "$PLAIN"
  info "使用已有明文 zip：$SRC"
fi

# ---------- 2. 结构检查 ----------
if ! unzip -t -q "$PLAIN" >/dev/null 2>&1; then
  die "打包结果未通过 unzip -t 校验"
fi
if ! unzip -Z1 "$PLAIN" | grep -q '^system/'; then
  warn "包内没有以 system/ 开头的条目，App 可能离线时找不到目标路径"
fi

# ---------- 3. AES-128-ECB 加密（openssl 自动加 PKCS#5 填充） ----------
openssl enc -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$PLAIN" -out "$TMPOUT" 2>/dev/null \
  || die "加密失败"

PLAIN_SIZE=$(wc -c <"$PLAIN" | tr -d ' ')
ENC_SIZE=$(wc -c <"$TMPOUT" | tr -d ' ')
[ $((ENC_SIZE % 16)) -eq 0 ] || die "密文长度 $ENC_SIZE 不是 16 的倍数，异常"

info "明文 $PLAIN_SIZE 字节 -> 密文 $ENC_SIZE 字节（PKCS#5 填充 $((ENC_SIZE - PLAIN_SIZE)) 字节）"

# ---------- 4. 落盘 ----------
if [ -z "$OUT" ]; then
  base="$(basename "$SRC")"
  case "$base" in
    *.decrypted) base="${base%.decrypted}" ;;
    *.zip)       base="${base%.zip}" ;;
  esac
  OUT="$(pwd)/${base}.zip"
fi
mkdir -p "$(dirname "$OUT")"
cp "$TMPOUT" "$OUT"
info "已输出：$OUT"

if [ "$KEEP" -eq 1 ]; then
  cp "$PLAIN" "${OUT%.zip}.plain.zip"
  info "中间明文已保留：${OUT%.zip}.plain.zip"
fi

# ---------- 5. 回环自校验：用解密脚本还原并逐字节比对 ----------
BACK="$WORK/back.zip"
openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$OUT" -out "$BACK" 2>/dev/null \
  || die "自校验失败：密文无法用同密钥解回"
if cmp -s "$BACK" "$PLAIN"; then
  info "回环校验通过：解密结果与打包明文逐字节一致"
else
  die "回环校验失败：解密结果与原文不一致"
fi

# ---------- 6. 汇总 ----------
echo
info "包内条目："
unzip -Z1 "$PLAIN" | sed 's/^/    /'
echo
info "把 $OUT 按原路径放回（或推送给 App）即可，App 端无需改动"