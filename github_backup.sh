#!/bin/bash

# Copy latest cowrie log
cp /home/cowrie/cowrie/var/log/cowrie/cowrie.json /home/cowrie/cowrie-analysis/cowrie_$(date +\%F_\%H).json

# Go to repo
cd /home/cowrie/cowrie-analysis

# Push to GitHub
git add .
git commit -m "Auto backup $(date)"
git push origin main
