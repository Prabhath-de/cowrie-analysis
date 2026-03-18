#!/bin/bash

# Go to repo
cd /home/cowrie/cowrie-analysis

# Create daily backup ONLY if not exists
FILE="cowrie_$(date +%F).json"

if [ ! -f "$FILE" ]; then
  cp /home/cowrie/cowrie/var/log/cowrie/cowrie.json "$FILE"

  git add .
  git commit -m "Daily backup $(date)"
  git push origin main
fi
