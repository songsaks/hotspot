#!/bin/bash

# 1. เข้าไปยังโฟลเดอร์โปรเจกต์ (แก้ตาม Path จริงบน Server)
PROJECT_DIR="/var/www/ninecom_hotspot"
cd $PROJECT_DIR

# 2. Activate Virtual Environment (ถ้าพี่ใช้ venv แก้ Path ตามจริง)
# source venv/bin/activate

# 3. รันคำสั่งสรุปยอดรายวัน (จะสรุปข้อมูลของเมื่อวานให้อัตโนมัติ)
# บันทึกผลลัพธ์ลงไฟล์ logs/daily_aggregation.log
mkdir -p logs
echo "--- Starting Aggregation at $(date) ---" >> logs/daily_aggregation.log
python3 manage.py aggregate_daily_stats >> logs/daily_aggregation.log 2>&1
echo "--- Finished Aggregation at $(date) ---" >> logs/daily_aggregation.log
