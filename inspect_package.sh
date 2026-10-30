#!/usr/bin/env bash
# =============================================================================
# inspect_package.sh —— 镜像包体检：解密 + 结构/权限/完整性诊断
#
# 支持三种输入：加密包（AES-128-ECB）、明文 zip、明文 apk
#
# 用法：
#   ./inspect_package.sh 包                    # 体检单个包
#   ./inspect_package.sh 我的包 --ref 原包      # 与原始包对比差异
# =============================================================================
set -uo pipefail

KEY_HEX="257a3839617669434d304b6b62457339"
KEY_RAW='%z89aviCM0KkbEs9'

die()  { printf '\033[31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }
hdr()  { printf '\n\033[36m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
note() { printf '  \033[33m!\033[0m %s\n' "$*"; }

command -v unzip >/dev/null 2>&1 || die "需要 unzip"
command -v openssl >/dev/null 2>&1 || die "需要 openssl"

[ $# -ge 1 ] || { sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
PKG="$1"; REF=""
shift
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:-}"; [ -n "$REF" ] || die "--ref 缺少参数"; shift 2 ;;
    *) die "未知参数：$1" ;;
  esac
done
[ -f "$PKG" ] || die "文件不存在：$PKG"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ---------- 归一化为明文 ----------
normalize() {  # $1=输入 $2=输出
  local f="$1" o="$2" magic
  magic=$(head -c 2 "$f")
  if [ "$magic" = "PK" ]; then
    cp "$f" "$o"; echo "plain"
    return 0
  fi
  if openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$f" -out "$o" 2>/dev/null \
     && [ "$(head -c 2 "$o")" = "PK" ]; then
    echo "aes"; return 0
  fi
  rm -f "$o"; echo "fail"; return 1
}

list_entries() {  # 输出 "mode method size name"
  unzip -Z "$1" 2>/dev/null \
    | grep -E '^[-dl][rwxSts-]{9} ' \
    | awk '{ m=$1; sz=$4; meth=$6; n=$9; for(i=10;i<=NF;i++) n=n" "$i; printf "%s\t%s\t%s\t%s\n", m, meth, sz, n }'
}

report() {
  local zip="$1" label="$2"
  hdr "$label"

  # 是否是 APK
  if unzip -Z1 "$zip" 2>/dev/null | grep -qx 'AndroidManifest.xml'; then
    local pkgsize; pkgsize=$(wc -c <"$zip" | tr -d ' ')
    note "这是一个 APK（含 AndroidManifest.xml），不是 system 镜像包"
    note "大小 $pkgsize 字节，条目 $(unzip -Z1 "$zip" | wc -l | tr -d ' ') 个"
    unzip -Z1 "$zip" | head -8 | sed 's/^/      /'
    return 0
  fi

  local total; total=$(list_entries "$zip" | wc -l | tr -d ' ')
  printf '  条目数：%s\n' "$total"

  # 顶层结构
  local tops ntop
  tops=$(list_entries "$zip" | awk -F'\t' '{split($4,a,"/"); print a[1]}' | sort -u)
  ntop=$(echo "$tops" | wc -l | tr -d ' ')
  printf '  顶层：%s\n' "$(echo "$tops" | tr '\n' ' ')"
  if [ "$ntop" -eq 1 ]; then
    case "$tops" in
      system)    ok "顶层是 system/（Superuser 镜像包，正确）" ;;
      androidfs) ok "顶层是 androidfs/（rootfs 镜像包，正确）" ;;
      *)         ok "顶层是单一目录 $tops/" ;;
    esac
  else
    bad "顶层有 $ntop 个并列项，解包后会散落在同一层，结构一定不对"
  fi
  if echo "$tops" | grep -qx 'system' && [ "$ntop" -gt 1 ]; then
    bad "system/ 不应该是顶层之一，说明多套了一层"
  fi

  # 符号链接 / setuid / 硬链接
  local nlink nsuid
  nlink=$(list_entries "$zip" | awk -F'\t' '$1 ~ /^l/' | wc -l | tr -d ' ')
  nsuid=$(list_entries "$zip" | awk -F'\t' '$1 ~ /s/ || $1 ~ /S/' | wc -l | tr -d ' ')
  printf '  符号链接：%s 个   setuid/setgid：%s 个\n' "$nlink" "$nsuid"
  if [ "$nlink" -eq 0 ] && [ "$ntop" -eq 1 ] && [ "$tops" = "androidfs" ]; then
    bad "rootfs 包里一个符号链接都没有 —— 极可能是用 zip 不带 -y 重打的，链接被展开了"
  fi
  [ "$nlink" -gt 0 ] && ok "符号链接以链接形式保存（lrwxrwxrwx）"
  [ "$nsuid" -gt 0 ] && ok "setuid 位在 zip 属性里保留"

  # 关键条目
  case "$tops" in
    system)
      for k in "system/xbin/daemonsu" "system/app/Superuser/Superuser.apk"; do
        if unzip -Z1 "$zip" | grep -qx "$k"; then ok "存在 $k"; else bad "缺失 $k"; fi
      done ;;
    androidfs)
      for k in "androidfs/init" "androidfs/system"; do
        if unzip -Z1 "$zip" | grep -q "^$k"; then ok "存在 $k"; else bad "缺失 $k"; fi
      done ;;
  esac

  # 权限
  local dmode=""
  [ "$tops" = "system" ] && dmode=$(list_entries "$zip" | awk -F'\t' '$4=="system/xbin/daemonsu"{print $1}')
  if [ -n "$dmode" ]; then
    case "$dmode" in
      -rwx*) ok "daemonsu 权限 $dmode" ;;
      *)     bad "daemonsu 权限是 $dmode（必须可执行 755，否则 su 起不来）" ;;
    esac
  fi

  # 压缩方式
  local stored
  stored=$(list_entries "$zip" | awk -F'\t' '$1 !~ /^d/ && $1 !~ /^l/ && $2=="stor" && $3+0 > 4096 {print $4}' | head -3)
  if [ -n "$stored" ]; then
    note "以下文件未压缩（stor）：$(echo $stored | tr '\n' ' ')"
  else
    ok "文件均为 deflate 压缩（与原始包一致）"
  fi

  # 异常条目
  local weird
  weird=$(list_entries "$zip" | awk -F'\t' '$4 ~ /^\// || $4 ~ /\.\.\//{print $4}')
  [ -n "$weird" ] && bad "存在绝对路径/上跳/软链接条目：$weird"

  # 大文件是否缺失
  local big
  big=$(list_entries "$zip" | awk -F'\t' '$3+0 > 500000 {printf "%s(%s) ", $4, $3}')
  printf '  >500KB 的条目：%s\n' "${big:-无}"

  echo
  echo "  条目清单："
  list_entries "$zip" | awk -F'\t' '{printf "    %-11s %-5s %10s  %s\n", $1, $2, $3, $4}'
}

# ---------- 主流程 ----------
hdr "输入：$PKG"
printf '  大小：%s 字节\n' "$(wc -c <"$PKG" | tr -d ' ')"
kind=$(normalize "$PKG" "$WORK/a.bin" || true)
case "$kind" in
  plain) note "输入已是明文（未加密）" ;;
  aes)   ok "AES-128-ECB 解密成功（密钥与原包一致）" ;;
  *)     die "解密失败：既不是明文，也不是该密钥的密文" ;;
esac

if ! unzip -t -q "$WORK/a.bin" >/dev/null 2>&1; then
  bad "ZIP 完整性校验失败（可能被截断或打包过程损坏）"
fi

report "$WORK/a.bin" "本包结构"

if [ -n "$REF" ]; then
  [ -f "$REF" ] || die "参考包不存在：$REF"
  rkind=$(normalize "$REF" "$WORK/b.bin" || true)
  [ "$rkind" = "fail" ] && die "参考包无法解密"
  report "$WORK/b.bin" "参考包结构"

  hdr "差异（参考包 -> 本包）"
  list_entries "$WORK/b.bin" | awk -F'\t' '{print $4"\t"$3}' | sort >"$WORK/ref.txt"
  list_entries "$WORK/a.bin" | awk -F'\t' '{print $4"\t"$3}' | sort >"$WORK/new.txt"
  if diff -q "$WORK/ref.txt" "$WORK/new.txt" >/dev/null; then
    ok "条目名与大小完全一致"
  else
    diff "$WORK/ref.txt" "$WORK/new.txt" | sed 's/^</  仅参考包有：/; s/^>/  仅本包有：/' | head -30
  fi
fi

hdr "结论"
echo "  若上面出现 ✗，按提示修正后重新加密；全为 ✓ 仍不识别，则是安装入口（URL 参数）或包内内容校验的问题。"