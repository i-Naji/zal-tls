#!/usr/bin/env python3
"""Extract RFC 8448's traces into a Nim test-data module:
   one entry per (section, step, label): the octets as a hex string."""
import json, re, sys
text = open(sys.argv[1]).read()
# Drop page footers/headers and form feeds.
lines = []
for l in text.split('\n'):
    if '\f' in l: continue
    if re.match(r'^Thomson\s+Informational', l) or re.match(r'^RFC 8448\s+TLS 1.3 Traces', l): continue
    lines.append(l)
sections = {'3': 'Simple', '4': 'Resumed', '5': 'Hrr', '6': 'ClientAuth', '7': 'Compat'}
cur = None; step = None; label = None; out = {k: [] for k in sections.values()}
i = 0
for l in lines:
    m = re.match(r'^(\d)\.  ', l)
    if m:
        cur = sections.get(m.group(1)); step = None; label = None; continue
    if cur is None: continue
    m = re.match(r'^   (\{\w+\}\s+.*?):?\s*$', l)
    if m and l.strip().startswith('{'):
        step = re.sub(r'\s+', ' ', m.group(1)).rstrip(':'); label = None; continue
    m = re.match(r'^      (.+?) \((\d+) octets?\):\s*(.*)$', l)
    if m and step:
        label = m.group(1).strip(); n = int(m.group(2)); hexs = '' if m.group(3).strip() == '(empty)' else m.group(3)
        out[cur].append([step, label, n, hexs.replace(' ', '')]); continue
    m = re.match(r'^\s{9,}([0-9a-f]{2}( [0-9a-f]{2})*)\s*$', l)
    if m and label and out[cur]:
        out[cur][-1][3] += m.group(1).replace(' ', ''); continue
    if l.strip() == '': continue
    label = None
bad = [(s, e[0], e[1]) for s, es in out.items() for e in es if len(e[3]) != 2 * e[2]]
if bad: sys.exit('length mismatch: %r' % bad[:5])
w = open(sys.argv[2], 'w')
w.write('## RFC 8448 (TLS 1.3 traces), extracted by tests/data/rfc8448.py: every\n')
w.write('## labelled octet string, by section, step and label.\n\n')
w.write('type TraceItem* = object\n  step*, label*, hex*: string\n\n')
for name, es in out.items():
    w.write('let %s* = @[\n' % name)
    for step, label, n, h in es:
        w.write('  TraceItem(step: %s, label: %s, hex: %s),\n' % (json.dumps(step), json.dumps(label), json.dumps(h)))
    w.write(']\n\n')
w.write('''proc startsWith(s, prefix: string): bool =
  if prefix.len > s.len: return false
  var i = 0
  while i < prefix.len:
    if s[i] != prefix[i]: return false
    i = i + 1
  result = true

proc nth*(items: seq[TraceItem]; step, label: string; n: int): string =
  ## The hex of `label` in the n-th (from 0) step whose text starts with `step`.
  result = ""
  var k = 0
  for it in items:
    if it.label == label and startsWith(it.step, step):
      if k == n: return it.hex
      k = k + 1

proc trace*(items: seq[TraceItem]; step, label: string): string =
  ## The hex of `label` in the first step whose text starts with `step`.
  result = nth(items, step, label, 0)
''')
print({k: len(v) for k, v in out.items()})
