#!/usr/bin/env bash
# =============================================================================
# replace_in_package.sh —— 在加密包里「就地替换文件」，不整包解压重打
#
# 为什么不用解包重打：rootfs 包（androidfs）里大量符号链接和 setuid 文件，
#   unzip 解包会丢 setuid，zip 不带 -y 重打会把链接展开成实体文件，
#   整包重打 = 结构被破坏。本脚本只改你指定的条目，其余条目字节级不动。
#
# 用法：
#   ./replace_in_package.sh 包 --set 包内路径=本地文件 [--set ...] [-o 输出] [-k]
#   ./replace_in_package.sh 包 --del 包内路径 [-o 输出]
#   ./replace_in_package.sh 包 --list                      # 只看内容不动
#
# 示例：
#   ./replace_in_package.sh superuser.zip \
#       --set system/app/Superuser/Superuser.apk=./新.apk \
#       --set system/xbin/daemonsu=./daemonsu -o 改好.zip
#
# 说明：替换后条目权限默认沿用包内原权限（不会因为本地文件是 644 就变成 644）；
#       需要强制指定时加 --mode 755。
# =============================================================================
set -uo pipefail

KEY_HEX="257a3839617669434d304b6b62457339"
KEY_RAW='%z89aviCM0KkbEs9'

die()  { printf '\033[31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[32m[信息]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[警告]\033[0m %s\n' "$*"; }

command -v openssl >/dev/null 2>&1 || die "需要 openssl"
command -v unzip   >/dev/null 2>&1 || die "需要 unzip"
command -v zip     >/dev/null 2>&1 || die "需要 zip"

# ---------- 参数 ----------
[ $# -ge 1 ] || { sed -n '12,24p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
PKG="$1"; shift
SETS=(); DELS=(); OUT=""; KEEP=0; MODE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --set)  [ $# -ge 2 ] || die "--set 需要 路径=文件"; SETS+=("$2"); shift 2 ;;
    --del)  [ $# -ge 2 ] || die "--del 需要 路径"; DELS+=("$2"); shift 2 ;;
    --mode) [ $# -ge 2 ] || die "--mode 需要八进制"; MODE="$2"; shift 2 ;;
    -o)     [ $# -ge 2 ] || die "-o 需要路径"; OUT="$2"; shift 2 ;;
    -k)     KEEP=1; shift ;;
    --list) LIST=1; shift ;;
    *)      die "未知参数：$1" ;;
  esac
done
[ -f "$PKG" ] || die "包不存在：$PKG"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PLAIN="$WORK/plain.zip"

# ---------- 归一化 ----------
if [ "$(head -c 2 "$PKG")" = "PK" ]; then
  cp "$PKG" "$PLAIN"; info "输入是明文 zip"
else
  openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$PKG" -out "$PLAIN" 2>/dev/null \
    || die "解密失败（填充校验不通过）"
  [ "$(head -c 2 "$PLAIN")" = "PK" ] || die "解密后不是 ZIP，密钥或文件不对"
  info "已解密为明文 zip：$(wc -c <"$PLAIN" | tr -d ' ') 字节"
fi

if [ "${LIST:-0}" = "1" ]; then
  zipinfo -l "$PLAIN" | grep -E '^[-dl]'
  exit 0
fi

[ ${#SETS[@]} -gt 0 ] || [ ${#DELS[@]} -gt 0 ] || die "没有指定 --set / --del，用 --list 可以只查看"

# 权限串 -> 八进制
mode2oct() {
  awk -v s="$1" 'BEGIN{
    out="";
    for(g=0;g<3;g++){
      v=0;
      c=substr(s,g*3+2,1); if(c=="r") v+=4;
      c=substr(s,g*3+3,1); if(c=="w") v+=2;
      c=substr(s,g*3+4,1); if(c=="x"||c=="s"||c=="t") v+=1;
      out=out v;
    }
    sp=0;
    c=substr(s,4,1);  if(c=="s"||c=="S") sp+=4;
    c=substr(s,7,1);  if(c=="s"||c=="S") sp+=2;
    c=substr(s,10,1); if(c=="t"||c=="T") sp+=1;
    if(sp>0) out=sp out;
    print out;
  }'
}

STAGE="$WORK/stage"
mkdir -p "$STAGE"

# ---------- 替换 ----------
for s in "${SETS[@]}"; do
  path="${s%%=*}"; src="${s#*=}"
  [ "$path" != "$src" ] || die "--set 格式应为 包内路径=本地文件：$s"
  [ -f "$src" ] || die "本地文件不存在：$src"

  if unzip -Z1 "$PLAIN" | grep -qx "$path"; then
    oldline=$(zipinfo -l "$PLAIN" "$path" | head -1)
    oldmode=$(echo "$oldline" | awk '{print $1}')
    use="${MODE:-$(mode2oct "$oldmode")}"
    info "替换 $path（原权限 $oldmode → $use）"
  else
    use="${MODE:-644}"
    warn "包内不存在 $path，将作为新条目添加（权限 $use）"
  fi

  mkdir -p "$STAGE/$(dirname "$path")"
  cp "$src" "$STAGE/$path"
  chmod "$use" "$STAGE/$path"
  ( cd "$STAGE" && zip -q -y "$PLAIN" "$path" ) || die "写入 $path 失败"
done

# ---------- 删除 ----------
for d in "${DELS[@]}"; do
  if unzip -Z1 "$PLAIN" | grep -qx "$d"; then
    zip -q -d "$PLAIN" "$d" || die "删除 $d 失败"
    info "已删除 $d"
  else
    warn "包内没有 $d，跳过"
  fi
done

# ---------- 校验 ----------
unzip -t -q "$PLAIN" >/dev/null 2>&1 || die "改动后 ZIP 校验失败"
left=$(list_count=$(unzip -Z1 "$PLAIN" | wc -l | tr -d ' '); echo "$list_count")
info "改动后条目数：$left"

# ---------- 输出 ----------
if [ -z "$OUT" ]; then
  base="${PKG%.zip}"; OUT="${base}.patched.zip"
fi
openssl enc -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$PLAIN" -out "$WORK/enc.bin" 2>/dev/null \
  || die "加密失败"
cp "$WORK/enc.bin" "$OUT"
info "已输出：$OUT（$(wc -c <"$OUT" | tr -d ' ') 字节）"

if [ "$KEEP" = "1" ]; then
  cp "$PLAIN" "${OUT%.zip}.plain.zip"
  info "明文已保留：${OUT%.zip}.plain.zip"
fi

# ---------- 回环 ----------
openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$OUT" -out "$WORK/back.zip" 2>/dev/null \
  || die "回环解密失败"
cmp -s "$WORK/back.zip" "$PLAIN" && info "回环校验通过" || die "回环校验失败"

# ---------- 未改动条目是否原样 ----------
if [ "$(head -c 2 "$PKG")" != "PK" ]; then
  openssl enc -d -aes-128-ecb -nosalt -K "$KEY_HEX" -in "$PKG" -out "$WORK/orig.zip" 2>/dev/null
  changed=$(comm -13 <(unzip -Z1 "$WORK/orig.zip" | sort) <(unzip -Z1 "$PLAIN" | sort) | tee /dev/stderr | wc -l)
  changed_ok=$(comm -12 <(unzip -Z1 "$WORK/orig.zip" | sort) <(unzip -Z1 "$PLAIN" | sort) | wc -l)
  info "保留共用条目 $changed_ok 个，新增 $changed 个"
fi

echo
info "完成。替换后的包可直接放回原位置"