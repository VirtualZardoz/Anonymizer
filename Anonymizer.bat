@echo off
title Anonymizer
echo Starting Anonymizer...
wsl -e bash -c "cd /mnt/d/~HAL-tools/anonymizer && python3 app.py"
pause
