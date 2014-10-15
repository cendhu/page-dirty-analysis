#!/usr/bin/python
import pyhash
import sys

def spooky_hash():
  hasher = pyhash.spooky_32();
  h = hasher(sys.argv[1])
  return h

spooky_hash()
