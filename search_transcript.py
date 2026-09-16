import json
import re

with open(r'C:\Users\NVX\.gemini\antigravity\brain\d157b902-77a0-4c16-8856-99a3b736fbe4\.system_generated\logs\transcript.jsonl', 'r', encoding='utf-8') as f:
    for line in f:
        if 'id=\"tab-ai\"' in line:
            print("Found tab-ai in transcript.jsonl")
            break
