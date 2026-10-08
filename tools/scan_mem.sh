#!/system/bin/sh
# 扫描目标进程内存中的关键词 (需 root)
PID=$1
shift
echo "== pid=$PID =="
cat /proc/$PID/maps | while read -r line; do
  perms=$(echo "$line" | cut -d' ' -f2)
  case "$perms" in
    rw*) ;;
    *) continue ;;
  esac
  range=$(echo "$line" | cut -d' ' -f1)
  start=${range%-*}
  end=${range#*-}
  startd=$((0x$start))
  endd=$((0x$end))
  size=$((endd - startd))
  # 只扫 64KB ~ 64MB 的区域
  if [ "$size" -lt 65536 ] || [ "$size" -gt 67108864 ]; then continue; fi
  cnt=$((size / 4096))
  skip=$((startd / 4096))
  for pat in "$@"; do
    n=$(busybox dd if=/proc/$PID/mem bs=4096 skip=$skip count=$cnt 2>/dev/null \
        | busybox grep -a -c "$pat" 2>/dev/null)
    if [ -n "$n" ] && [ "$n" != "0" ]; then
      echo "HIT range=$range size=$size skip=$skip cnt=$cnt pat=$pat lines=$n"
    fi
  done
done
echo "== done =="
