#!/usr/bin/env python3
"""Reject private network addresses, credentials and emails in publish set."""
from pathlib import Path
import re
root=Path(__file__).resolve().parent.parent
rules=[
 ("RFC1918",re.compile(r"\b(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?\b")),
 ("PRIVATE_KEY",re.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----")),
 ("CREDENTIAL",re.compile(r"(?:hf_|ghp_|github_pat_)[A-Za-z0-9_]{24,}")),
 ("EMAIL",re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+\.[A-Za-z]{2,}"))]
files=[p for p in root.rglob("*") if p.is_file() and p.suffix in (".rs",".md",".hbi",".hbp",".toml",".py",".sha256") and p.name!="privacy_scan.py"]
assert len(files)>=5
for file in files:
    for title,pattern in rules:
        if pattern.search(file.read_text()): raise RuntimeError("PUBLIC_SAFETY_FAIL:"+title+":"+str(file.relative_to(root)))
print("PRIVACY|files="+str(len(files))+"|credentials=0|private_keys=0|lan=0|emails=0|json=0")
