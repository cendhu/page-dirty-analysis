import os
import math
import random
import subprocess
import json

AVG_CHUNK_SIZE = 4096 #4KB
MASK = (2 ** 32) - 1
READ_CHUNK_SIZE = 4096*4 #Read 16 KB at a time!
'''
Analyze the two dump files byte by byte. Take each byte and then 
a bitwise XOR of the two to know the difference. Write the difference 
to the file xorfile.
'''
def analyze_dumps_bbb(dump1, dump2, xorfile):
  f1 = open(dump1, "rb")
  f2 = open(dump2, "rb")
  f_bin = open(xorfile, "wb")
  try:
    byte1 = bytearray(f1.read())
    byte2 = bytearray(f2.read())
    for i in range(len(byte1)):
      old_byte = byte1[i]
      byte1[i] = byte1[i] ^ byte2[i]
      #if byte1[i] != old_byte and byte1[i]!=0:
        #print("change! ",i)
      #new_byte = bytes(new_int)
    f_bin.write(byte1)
  finally:
    f_bin.close()
    f1.close()
    f2.close()

'''
Does the same job as the above function analyze_dumps_bbb but improves on
memory requirements of the function to analyze large files.
'''
def analyze_dumps_bbb_mem(dump1, dump2, final_dump):
  f1 = open(dump1, "rb")
  f1.seek(0,os.SEEK_END)
  size1 = f1.tell()
  f1.seek(0,0)
  f2 = open(dump2, "rb")
  f2.seek(0,os.SEEK_END)
  size2 = f2.tell()
  f2.seek(0,0)
  f_bin = open(final_dump, "wb")
  one_time_chunk = 100*1024*1024 #100 MB at a time
  if size1 != size2:
    print("Dump sizes not compatible!")
    exit(1)

  elif size1 <= one_time_chunk:
    try:
      byte1 = bytearray(f1.read())
      byte2 = bytearray(f2.read())
      for i in range(len(byte1)):
        old_byte = byte1[i]
        byte1[i] = byte1[i] ^ byte2[i]
      f_bin.write(byte1)
    finally:
      f_bin.close()
      f1.close()
      f2.close()

  else:
    loop_count = int(size1/one_time_chunk) if ((size1 % one_time_chunk) == 0) else int((size1/one_time_chunk) + 1)
    last_remain_size = 0 if ((size1 % one_time_chunk) == 0) else (size1 - ((loop_count-1) * one_time_chunk)) 
    try:
      count = 1
      while count <= loop_count:
        if count != loop_count:
          byte1 = bytearray(f1.read(one_time_chunk))
          byte2 = bytearray(f2.read(one_time_chunk))
        else:
          byte1 = bytearray(f1.read(last_remain_size))
          byte2 = bytearray(f2.read(last_remain_size))
        for i in range(len(byte1)):
          old_byte = byte1[i]
          byte1[i] = byte1[i] ^ byte2[i]
        f_bin.write(byte1)
        count = count + 1
    finally:
      f_bin.close()
      f1.close()
      f2.close()

'''
Get lists of dirty pages in the memory area. Analyze the file to 
which XOR values were written in analyze_dumps_bbb.
'''
def get_dirty_pages(dumpfile):
  f = open(dumpfile, "rb")
  f.seek(0,os.SEEK_END)
  size = f.tell()
  f.seek(0,0)
  print("Size of dump : ",size, "Bytes")
  count = int(size/4096)
  print("Page Count : ",count)
  dirty_pages=[]
  dirtiness_dict = {}
  continuity_dict = {}
  page_num = 0
  while (page_num != count):
    #print("Page num ",page_num)
    cur_page = bytearray(f.read(4096))
    page_num = page_num + 1
    cur_page_inserted = 0
    dirty_bytes = 0
    prev_index = 0
    is_continuous = 1
    for i in range(len(cur_page)):
      #print("byte ",cur_page[i], " page : ",page_num)
      if cur_page[i] != 0:
        dirty_bytes = dirty_bytes + 1
        if cur_page_inserted == 0:
          dirty_pages.append(page_num)
          cur_page_inserted = 1
        if (i - prev_index) > 1:
          is_continuous = 0
        prev_index = i
    if cur_page_inserted == 1:
      dirtiness = (dirty_bytes/4096)*100
      dirtiness = round(dirtiness,3)
      dirtiness_dict[page_num] = dirtiness
      continuity_dict[page_num] = is_continuous
        
  return (dirtiness_dict, continuity_dict)

def sha256hashing(pnum1, pnum2, dumpfile):
  import hashlib as hl
  f = open(dumpfile, "rb")
  f.seek((pnum1-1)*4096,0)
  b1 = bytearray(f.read(4096))
  f.seek((pnum2-1)*4096,0)
  b2 = bytearray(f.read(4096))
  hash_obj1 = hl.sha256(b1)
  hash1 = hash_obj1.hexdigest()
  hash_obj2 = hl.sha256(b2)
  hash2 = hash_obj2.hexdigest()
  return(hash1 == hash2)

def findSHA256hash(num, nbytes, fptr):
  import hashlib as hl
  fptr.seek((num-1)*nbytes,0)
  a = bytearray(fptr.read(nbytes))
  hash_obj = hl.sha256(a)
  hash_1 = hash_obj.hexdigest()
  return hash_1

'''
Find the duplicate pages and put them to separate lists. All zero-pages
excluded!
'''
def FindDuplicatePages(dumpfile):
  pageHashtable = {}
  duplicates_dict={}
  f = open(dumpfile,"rb")
  f.seek(0,os.SEEK_END)
  size = f.tell()
  num_pages = int(size/4096)
  f.seek(0,0)
  page_num = 1
  collision_count = 0
  while page_num != num_pages:
    cur_page = bytearray(f.read(4096))
    sha256hash_val = findSHA256hash(page_num, 4096, f) 
    if (sha256hash_val in pageHashtable) and (sha256hash_val in duplicates_dict):
      collision_count = collision_count + 1
      duplist = duplicates_dict[sha256hash_val]
      duplist.append(page_num)
      duplicates_dict[sha256hash_val] = duplist
    else:
      pageHashtable[sha256hash_val] = page_num
      all_zeroes = 1
      for i in range(len(cur_page)):
        if cur_page[i] != 0:
          all_zeroes = 0
          break
      dup_list = []
      if all_zeroes == 0:
        dup_list.append(page_num)
        duplicates_dict[sha256hash_val] = dup_list
    page_num = page_num + 1
  duplicates_list = []
  for k in duplicates_dict:
    duplicates_list.append(duplicates_dict[k])
  return (duplicates_list, collision_count)

'''
Find sub-page level duplicates. Divide each page in 'n' parts and
prepare lists for sub-duplicates.
'''
def SubPageDuplicates(dumpfile,n):
  subpageHashTable = {}
  f = open(dumpfile, "rb")
  f.seek(0, os.SEEK_END)
  size = f.tell()
  num_pages = int(size/4096)
  num_blocks = num_pages*n
  f.seek(0,0)
  page_num = 1
  block_num = 1
  while page_num != num_pages:
    cur_subpage = bytearray(f.read(int(4096/n)))
    sha256hash_val = findSHA256hash(block_num, int(4096/n), f)
    if sha256hash_val in subpageHashTable:
      sub_duplist = subpageHashTable[sha256hash_val]
      duplist = []
      duplist.append(page_num)
      duplist.append(block_num)
      sub_duplist.append(duplist)
      subpageHashTable[sha256hash_val] = sub_duplist
      block_num = block_num + 1
    else:
      all_zeroes = 1
      for i in range(len(cur_subpage)):
        if cur_subpage[i] != 0:
          all_zeroes = 0
          break
      duplist = []
      duplist.append(page_num)
      duplist.append(block_num)
      sub_duplist = []
      sub_duplist.append(duplist)
      if all_zeroes == 0:
        subpageHashTable[sha256hash_val] = sub_duplist
      block_num = block_num + 1
    if block_num > n:
      page_num = page_num + 1
      block_num = 1
  return subpageHashTable

def print_bytes(XORdump):
  f = bytearray(open(XORdump, "rb").read())
  for i in range(len(f)):
    if f[1]:
      print("Byte ",i," : ",f[i])

'''
Function to calculate mask given the number of MSBs
'''
def GetMask(n):
  mask = (2 ** (n)-1) << (32 - n)
  return mask

'''
Construct GearTable, a mapping of each byte of the dump 
with a random integer
'''
def GenerateGearTable():
  GearTable = {}
  for i in range(256):
    rand_int = random.randint(i,1000000000)
    GearTable[i] = rand_int
  return GearTable


'''
Gear based chunking implementation. Takes dump file name as input
and returns a list of binary string chunks generated by gear hashing
and chunking.
'''
def GearChunkingBulk(dumpfile, magicval):
  finger_print = 0
  pos = 0
  last = 0
  chunks = []
  num_significant_bits = int(math.log(AVG_CHUNK_SIZE,2))
  mask = GetMask(num_significant_bits)
  print(mask)
  GearTable = GenerateGearTable()
  f = open(dumpfile, "rb")
  f.seek(0,os.SEEK_END)
  size = f.tell()
  f.seek(0,0)
  byte_array = bytearray(f.read())
  l = len(byte_array)
  while pos < l:
    finger_print = ((finger_print << 1) + GearTable[byte_array[pos]]) & MASK
    #if(pos%1000 == 0):
      #print("pos : ",pos)
    if finger_print & mask == magicval:
      numbytes = pos - last
      new_array = byte_array[last+1:pos+1]
      new_array = str(new_array)
      chunks.extend(new_array)
      last = pos
    pos = pos + 1
  return chunks

'''
Gear based chunking implementation. Takes dump file name as input
and returns a list of binary string chunks generated by gear hashing
and chunking.
'''
def GearChunking(dumpfile, magicval):
  chunks = []
  num_significant_bits = int(math.log(AVG_CHUNK_SIZE,2))
  mask = GetMask(num_significant_bits)
  print(mask)
  GearTable = GenerateGearTable()
  f = open(dumpfile, "rb")
  f.seek(0,os.SEEK_END)
  size = f.tell()
  f.seek(0,0)
  rounds = int(size/READ_CHUNK_SIZE)
  last_bytes = size % READ_CHUNK_SIZE
  n=0
  if size >= READ_CHUNK_SIZE:
    while n < rounds:
      byte_array = bytearray(f.read(READ_CHUNK_SIZE))
      l = len(byte_array)
      finger_print = 0
      pos = 0
      last = 0
      while pos < l:
        finger_print = ((finger_print << 1) + GearTable[byte_array[pos]]) & MASK
        #if(pos%1000 == 0):
          #print("pos : ",pos)
        if finger_print & mask == magicval:
          numbytes = pos - last
          new_array = byte_array[last+1:pos+1]
          new_array = str(new_array)
          new_array = new_array[12:]
          new_array = new_array[:-2]
          chunks.append(new_array)
          last = pos
        pos = pos + 1
      n = n+1
    #n=rounds
    byte_array = bytearray(f.read(last_bytes))
    l = last_bytes
    finger_print = 0
    pos = 0
    last = 0
    while pos < l:
      finger_print = ((finger_print << 1) + GearTable[byte_array[pos]]) & MASK
      #if(pos%1000 == 0):
        #print("pos : ",pos)
      if finger_print & mask == magicval:
        numbytes = pos - last
        new_array = byte_array[last+1:pos+1]
        new_array = str(new_array)
        new_array = new_array[12:]
        new_array = new_array[:-2]
        chunks.append(new_array)
        last = pos
      pos = pos + 1
  else:
    byte_array = bytearray(f.read(last_bytes))
    l = last_bytes
    finger_print = 0
    pos = 0
    last = 0
    while pos < l:
      finger_print = ((finger_print << 1) + GearTable[byte_array[pos]]) & MASK
      #if(pos%1000 == 0):
        #print("pos : ",pos)
      if finger_print & mask == magicval:
        numbytes = pos - last
        new_array = byte_array[last+1:pos+1]
        new_array = str(new_array)
        new_array = new_array[12:]
        new_array = new_array[:-2]
        chunks.append(new_array)
        last = pos
      pos = pos + 1
  return chunks

'''
Get a dictionary containing Spooky hashes of each chunk.
'''
def GetSpookyHashes(source_chunks):
  #source_hashes = subprocess.call(["python2","spooky_hash.py", json.dumps(source_chunks)])
  source_hashes = {}
  l = len(source_chunks)
  for i in range(l):
    spooky = subprocess.call(["python2","spooky_tgt.py", source_chunks[i]])
    source_hashes[spooky] = source_chunks[i]
  return source_hashes

'''
Find Ddelta duplicates.
'''
def DdeltaDuplicates(source,target):
  source_hashes = GetSpookyHashes(source)
  duplicates = {}
  num_dups = 0
  l = len(target)
  print("len of target : ",l)
  for i in range(l):
    t_spooky = subprocess.call(["python2", "spooky_tgt.py", target[i]])
    if t_spooky in source_hashes:
      list_dup = duplicates[t_spooky]
      list_dup.append(target[i])
      duplicates[t_spooky] = list_dup
      num_dups = num_dups + 1
    else:
      list_dup = []
      list_dup.append(target[i])
      duplicates[t_spooky] = list_dup
  return duplicates
 
'''
Call whatever functions we need here.
'''
if __name__ == "__main__":
  mask = (2 ** 12 -1) << (20)#GetMask(num_significant_bits)
  tgt = GearChunking("new_dump.dump",mask)
  print("Done 1")
  src = GearChunking("file4.dump",mask)
  print("Done 2")
  print(len(src), " ", len(tgt))
  dups = DdeltaDuplicates(src,tgt)
  #analyze_dumps_bbb_mem("file4.dump", "file16.dump", "dirty_dump.bin")
  '''
  result = get_dirty_pages("dirty_dump.bin")
  print("List of dirty pages with percentage dirtiness :\n",result)
  duplicates = FindDuplicatePages("file16.dump")
  duplist = duplicates[0]
  print("List of duplicate pages :\n")
  group_num = 1
  for list1 in duplist:
    if(len(list1)) > 1:
      print(group_num," : ",list1)
      group_num = group_num + 1
  subpage_dict = SubPageDuplicates("file16.dump",4)
  print("Dictionary of sub page level duplicates : \n",subpage_dict)
  '''

