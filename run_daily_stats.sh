#!/bin/bash

# 1. เข้าไปยังโฟลเดอร์โปรเจกต์ (แก้ตาม Path จริงบน Server)
# จาก LOG พบว่าอยู่ที่ /var/www/hotspot
PROJECT_DIR="/var/www/hotspot"
cd $PROJECT_DIR

# 2. รันคำสั่งสรุปยอดรายวัน โดยใช้ Python จากใน Virtual Environment โดยตรง
# (เพื่อป้องกันปัญหาหา Module Django ไม่เจอเวลา Cron ทำงาน)
VENV_PYTHON="$PROJECT_DIR/venv/bin/python"

mkdir -p logs
echo "--- Starting Aggregation at $(date) ---" >> logs/daily_aggregation.log

if [ -f "$VENV_PYTHON" ]; then
    $VENV_PYTHON manage.py aggregate_daily_stats >> logs/daily_aggregation.log 2>&1
else
    # Fallback กรณีหา venv ไม่เจอ
    python3 manage.py aggregate_daily_stats >> logs/daily_aggregation.log 2>&1
fi

echo "--- Finished Aggregation at $(date) ---" >> logs/daily_aggregation.log
