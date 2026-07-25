---
title: GA 05 Q04 Scanner
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# Skill Safety Audit Scanner

This is a FastAPI scanner deployed on Hugging Face Spaces for the Skill Safety Audit assignment (GA_05 Q4).
It scans skill files for:
- `hardcoded_secret`
- `excessive_permissions`
- `prompt_injection`
