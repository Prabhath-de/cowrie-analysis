#!/bin/bash

# Go to repo
cd /home/cowrie/cowrie-analysis

# File path inside backups folder
FILE="backups/cowrie_$(date +%F).json"

# Create daily backup ONLY if not exists
if [ ! -f "$FILE" ]; then
  cp /home/cowrie/cowrie/var/log/cowrie/cowrie.json "$FILE"

  git add .
  git commit -m "Daily backup $(date)"
  git push origin main
fi
