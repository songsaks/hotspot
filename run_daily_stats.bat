@echo off
cd /d d:\DjangoProjects\ninecom_hotspot
python manage.py aggregate_daily_stats
echo Stats aggregated successfully at %date% %time% >> daily_stats_log.txt
