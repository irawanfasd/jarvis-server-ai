#!/bin/bash
sync && echo 3 > /proc/sys/vm/drop_caches
echo "✅ Cache RAM berhasil dibersihkan."
