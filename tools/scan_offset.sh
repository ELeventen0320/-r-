#!/system/bin/sh
# 在指定内存区域内按字节偏移定位关键词 (需 root)
# 用法: scan_offset.sh <pid> <start_hex> <size_hex> <pat>...
PID=$1
START=$2
SIZE=$3
shift 3
skip=$(( START / 4096 ))
cnt=$(( SIZE / 4096 ))
echo "== pid=$PID start=$START size=$SIZE skip=$skip cnt=$cnt =="
for pat in "$@"; do
  echo "--- pat=$pat ---"
  busybox dd if=/proc/$PID/mem bs=4096 skip=$skip count=$cnt 2>/dev/null \
    | busybox grep -abo "$pat" 2>/dev/null | head -40
done
echo "== done =="
