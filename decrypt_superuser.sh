#!/usr/bin/env bash
# =============================================================================
# decrypt_superuser.sh —— 解密 Superuser 镜像包（AES-128-ECB / 固定密钥）
#
# 算法来源：com.android.vmcore.installer.ImageInstallerV1
#   Cipher.getInstance("AES")  ->  AES/ECB/PKCS5Padding
#   SecretKeySpec("%z89aviCM0KkbEs9".getBytes(), "AES")
#
# 用法：
#   ./decrypt_superuser.sh superuser.zip              # 解密为 superuser.decrypted.zip
#   ./decrypt_superuser.sh superuser.zip -o out.zip   # 指定输出
#   ./decrypt_superuser.sh superuser.zip -x           # 解密并解包到 ./superuser/
#   ./decrypt_superuser.sh *.zip -x                   # 批量处理
# =============================================================================
set -euo pipefail

# 16 字节密钥 "%z89aviCM0KkbEs9" 的十六进制表示
KEY_HEX="257a3839617669434d304b6b62457339"
KEY_RAW='%z89aviCM0KkbEs9'

OUT=""
EXTRACT=0

die() { printf '\033[31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[32m[信息]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[警告]\033[0m %s\n' "$*"; }

usage() { sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

# ---------- 参数解析 ----------
if [ $# -eq 0 ]; then usage; fi
FILES=()
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output) [ $# -ge 2 ] || die "-o 需要一个参数"; OUT="$2"; shift 2 ;;
    -x|--extract) EXTRACT=1; shift ;;
    -h|--help) usage ;;
    -*) die "未知选项：$1" ;;
    *) FILES+=("$1"); shift ;;
  esac
done
if [ ${#FILES[@]} -eq 0 ]; then usage; fi
if [ ${#FILES[@]} -gt 1 ] && [ -n "$OUT" ]; then die "-o 只能配合单个输入文件使用"; fi

command -v openssl >/dev/null 2>&1 || die "未找到 openssl，请先安装（apt install openssl / brew install openssl）"

# ---------- 单文件解密 ----------
decrypt_one() {
  local src="$1" dst="$2" size

  [ -f "$src" ] || die "文件不存在：$src"
  size=$(wc -c <"$src" | tr -d ' ')

  # 已经是明文 zip 就直接跳过，避免重复处理
  if [ "$(head -c 2 "$src")" = "PK" ]; then
    warn "$src 已经是明文 ZIP，跳过"
    return 0
  fi

  if [ $((size % 16)) -ne 0 ]; then
    warn "$src 长度 $size 不是 16 的倍数，可能不是该格式的分组密文"
  fi

  info "输入：$src（$size 字节）"
  info "算法：AES-128-ECB / PKCS5Padding"

  # 方案 A：AES-128-ECB（openssl enc 会自动校验并剔除 PKCS#5 填充）
  local ok=0
  if openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$src" -out "$dst" 2>/dev/null; then
    if [ "$(head -c 2 "$dst")" = "PK" ]; then ok=1; fi
  fi

  # 方案 B：同一密钥当循环异或键（该 App 的另一条发布分支）
  if [ "$ok" -eq 0 ]; then
    warn "AES 分支未解出 ZIP，尝试异或分支…"
    perl -e '
      open my $f,"<:raw",$ARGV[0] or exit 1; local $/; my $d=<$f>;
      my $k=$ARGV[2]; my $n=length($k); my $o="";
      for my $i (0..length($d)-1){ $o .= chr(ord(substr($d,$i,1)) ^ ord(substr($k,$i%$n,1))); }
      open my $g,">:raw",$ARGV[1] or exit 1; print $g $o;
    ' "$src" "$dst" "$KEY_RAW" 2>/dev/null || true
    if [ "$(head -c 2 "$dst" 2>/dev/null)" = "PK" ]; then ok=1; fi
  fi

  if [ "$ok" -eq 0 ]; then
    rm -f "$dst"
    die "解密失败：AES 与异或两条分支均未命中，该文件不是此密钥对应的加密镜像"
  fi

  local osize; osize=$(wc -c <"$dst" | tr -d ' ')
  info "输出：$dst（$osize 字节，魔数 $(head -c 2 "$dst")）"

  # ---------- 解包 ----------
  if [ "$EXTRACT" -eq 1 ]; then
    local dir
    case "$dst" in
      *.zip) dir="${dst%.zip}" ;;
      *)     dir="${dst}.extracted" ;;
    esac
    mkdir -p "$dir"
    if command -v unzip >/dev/null 2>&1; then
      if unzip -o -q "$dst" -d "$dir"; then info "已解包到：$dir"; else warn "解包失败"; fi
    else
      warn "未找到 unzip，跳过解包"
    fi
  fi

  # ---------- 完整性校验 ----------
  if command -v unzip >/dev/null 2>&1; then
    if unzip -t -q "$dst" >/dev/null 2>&1; then
      info "ZIP 完整性校验：通过"
    else
      warn "ZIP 校验未通过（可能原文件不完整）"
    fi
  fi
  echo
}

# ---------- 主流程 ----------
for f in "${FILES[@]}"; do
  if [ -n "$OUT" ]; then
    decrypt_one "$f" "$OUT"
  else
    base="${f%.*}"
    if [ "$base" = "$f" ]; then base="$f.out"; fi
    decrypt_one "$f" "${base}.decrypted.zip"
  fi
done

info "全部完成"