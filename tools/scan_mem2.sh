#!/system/bin/sh
# 扫描目标进程所有可读内存区域, 定位游戏自身字面量
PID=$1
shift
echo "== pid=$PID patterns: $* =="
cat /proc/$PID/maps | while read -r line; do
  perms=$(echo "$line" | cut -d' ' -f2)
  case "$perms" in
    r*) ;;
    *) continue ;;
  esac
  range=$(echo "$line" | cut -d' ' -f1)
  start=${range%-*}
  end=${range#*-}
  startd=$((0x$start))
  endd=$((0x$end))
  size=$((endd - startd))
  if [ "$size" -lt 4096 ] || [ "$size" -gt 268435456 ]; then continue; fi
  cnt=$((size / 4096))
  skip=$((startd / 4096))
  path=$(echo "$line" | cut -d' ' -f6)
  for pat in "$@"; do
    n=$(busybox dd if=/proc/$PID/mem bs=4096 skip=$skip count=$cnt 2>/dev/null \
        | busybox grep -a -c "$pat" 2>/dev/null)
    if [ -n "$n" ] && [ "$n" != "0" ]; then
      echo "HIT pat=$pat range=$range size=$size lines=$n path=$path"
    fi
  done
done
echo "== done =="
