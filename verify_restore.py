#!/usr/bin/env python3
"""Verify every original file; optionally restore full snapshot into a new directory."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--restore', type=Path, help='New, nonexistent output directory')
args = parser.parse_args()
root = Path(__file__).resolve().parent
manifest = json.loads((root / 'MANIFEST.json').read_text())
if args.restore:
    args.restore.mkdir(parents=True, exist_ok=False)
    for directory in manifest['directories']:
        (args.restore / directory).mkdir(parents=True, exist_ok=True)
for entry in manifest['files']:
    blocks = []
    if 'parts' in entry:
        for part in entry['parts']:
            block = (root / part['path']).read_bytes()
            if len(block) != part['bytes'] or hashlib.sha256(block).hexdigest() != part['sha256']:
                raise SystemExit('Part verification failed: ' + part['path'])
            blocks.append(block)
    else:
        blocks.append((root / entry['path']).read_bytes())
    data = b''.join(blocks)
    if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise SystemExit('File verification failed: ' + entry['path'])
    if args.restore:
        target = args.restore / entry['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(int(entry['mode'], 8))
print(f"Verified {len(manifest['files'])} original files; "
      f"{sum(f['bytes'] for f in manifest['files'])} bytes.")
