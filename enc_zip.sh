#!/usr/bin/env bash
# =============================================================================
# enc_zip.sh —— 直接把已打好的 zip/apk 加密（不打包、不改结构）
#
# 算法：AES-128-ECB / PKCS#5Padding，密钥 "%z89aviCM0KkbEs9"
#       ECB 无随机 IV，同一明文每次加密结果完全一致（可复现）
#
# 用法：
#   ./enc_zip.sh 我的.zip                     # -> 我的.enc.zip
#   ./enc_zip.sh 我的.zip -o 最终.zip          # 指定输出名
#   ./enc_zip.sh a.zip b.zip c.apk            # 批量
#   ./enc_zip.sh 我的.zip --overwrite         # 原地替换（先存 .bak）
#   ./enc_zip.sh 我的.zip -q                  # 只输出结果路径
#   ./enc_zip.sh my.zip --ref yuanrom.zip --fix -o rom1.zip
#
# 默认不覆盖输入文件；加密后自动解密回验 + ZIP 完整性校验。
# =============================================================================
set -uo pipefail

KEY_HEX="257a3839617669434d304b6b62457339"

die()  { printf '\033[31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[32m[信息]\033[0m %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[警告]\033[0m %s\n' "$*"; }

command -v openssl >/dev/null 2>&1 || die "需要 openssl"

[ $# -ge 1 ] || { sed -n '4,15p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

OUT=""; OVER=0; QUIET=0; FILES=()
while [ $# -gt 0 ]; do
  case "$1" in
    -o)          [ $# -ge 2 ] || die "-o 需要参数"; OUT="$2"; shift 2 ;;
    --overwrite) OVER=1; shift ;;
    -q)          QUIET=1; shift ;;
    -h|--help)   sed -n '4,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)          die "未知参数：$1" ;;
    *)           FILES+=("$1"); shift ;;
  esac
done
[ ${#FILES[@]} -gt 0 ] || die "没有输入文件"
if [ -n "$OUT" ] && [ ${#FILES[@]} -gt 1 ]; then die "-o 只能配合单个输入"; fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

count=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || { warn "跳过（不存在）：$f"; continue; }

  if [ "$(head -c 2 "$f")" != "PK" ]; then
    warn "跳过（开头不是 PK，可能已加密）：$f"
    continue
  fi

  SZ=$(wc -c <"$f" | tr -d ' ')
  PAD=$(( (16 - SZ % 16) % 16 )); [ "$PAD" -eq 0 ] && PAD=16
  ESZ=$(( SZ + PAD ))

  # 目标路径
  if [ -n "$OUT" ]; then
    dst="$OUT"
  elif [ "$OVER" = "1" ]; then
    dst="$f"
  else
    case "$f" in
      *.zip) dst="${f%.zip}.enc.zip" ;;
      *)     dst="${f}.enc" ;;
    esac
  fi

  [ "$QUIET" = "1" ] || printf '\n\033[36m== %s ==\033[0m\n' "$f"
  [ "$QUIET" = "1" ] || printf '  %s 字节（16 对齐？%s）\n' "$SZ" "$([ $((SZ % 16)) -eq 0 ] && echo 是 || echo 否)"

  openssl enc -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$f" -out "$WORK/e.bin" 2>/dev/null \
    || die "加密失败：$f"
  ACT=$(wc -c <"$WORK/e.bin" | tr -d ' ')
  [ "$ACT" -eq "$ESZ" ] || die "密文长度异常：期望 $ESZ，实际 $ACT"
  [ $((ACT % 16)) -eq 0 ] || die "密文不是 16 的倍数"

  if [ "$OVER" = "1" ] && [ "$dst" = "$f" ]; then
    cp "$f" "${f}.bak" || die "备份失败"
    [ "$QUIET" = "1" ] || info "原文件已备份为 ${f}.bak"
  fi

  cp "$WORK/e.bin" "$dst"

  # 回验
  openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$dst" -out "$WORK/d.bin" 2>/dev/null \
    || die "回验失败：无法解密"
  if cmp -s "$WORK/d.bin" "$f"; then
    [ "$QUIET" = "1" ] || ok "解密回验：与原文逐字节一致"
  else
    die "回验失败：解密结果与原文不一致"
  fi

  if command -v unzip >/dev/null 2>&1; then
    unzip -t -q "$WORK/d.bin" >/dev/null 2>&1 \
      && { [ "$QUIET" = "1" ] || ok "ZIP 完整性：通过"; } \
      || { [ "$QUIET" = "1" ] || warn "ZIP 完整性：未通过（可能不是 zip，或结构已损）"; }
  fi

  [ "$QUIET" = "1" ] && echo "$dst" || info "输出：$dst（$ACT 字节，填充 $PAD 字节）"
  count=$((count+1))
done

[ "$QUIET" = "1" ] || { echo; info "完成，共处理 $count 个文件"; }