#!/usr/bin/python
import pyhash
import sys
import json

def spooky_hash():
  spooky_hashes = {}
  hasher = pyhash.spooky_32();
  cmd_args = sys.argv[1]
  chunks = json.loads(cmd_args)
  l = len(chunks)
  for i in range(l):
    h = hasher(chunks[i])
    spooky_hashes[h] = chunks[i]
  return spooky_hashes

spooky_hash()
