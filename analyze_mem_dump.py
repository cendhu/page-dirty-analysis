import os

def analyze_dumps(dump1, dump2):
  f1_bytes = open(dump1, "rb").read()
  f2_bytes = open(dump2, "rb").read()
  f_bin = open("dirty_dump.bin", "wb")
  f_dec = open("dirty_dump.dec","w")
  try:
    print(len(f1_bytes))
    for index in range(len(f1_bytes)):
      #if index%10000000 == 0:
      #print(f1_bytes[index]," ",f2_bytes[index])
      new_int = f1_bytes[index] ^ f2_bytes[index]
      new_byte = bytes(new_int)
      new_binary = bin(new_int)[2:]
      #if index%10000000 == 0:
      #print(new_int,">>>>>",new_byte)
      f_bin.write(new_byte)
      f_dec.write(new_binary)
  finally:
    f_dec.close()
    f_bin.close()

def analyze_dumps_bbb(dump1, dump2):
  f1 = open(dump1, "rb")
  f2 = open(dump2, "rb")
  f_bin = open("dirty_dump.bin", "wb")
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

def get_dirty_pages(dumpfile):
  f = open(dumpfile, "rb")
  f.seek(0,os.SEEK_END)
  size = f.tell()
  f.seek(0,0)
  print("Size of dump : ",size, "Bytes")
  count = size/4000
  print("Page Count : ",count)
  dirty_pages=[]
  dirtiness_dict = {}
  page_num = 0
  while (page_num != count):
    #print("Page num ",page_num)
    cur_page = bytearray(f.read(4000))
    page_num = page_num + 1
    cur_page_inserted = 0
    dirty_bytes = 0
    for i in range(len(cur_page)):
      #print("byte ",cur_page[i], " page : ",page_num)
      if cur_page[i] != 0:
        dirty_bytes = dirty_bytes + 1
        if cur_page_inserted == 0:
          dirty_pages.append(page_num)
          cur_page_inserted = 1
    if cur_page_inserted == 1:
      dirtiness = (dirty_bytes/4000)*100
      dirtiness = round(dirtiness,3)
      dirtiness_dict[page_num] = dirtiness
        
  return dirtiness_dict

def print_bytes(XORdump):
  f = bytearray(open(XORdump, "rb").read())
  for i in range(len(f)):
    if f[1]:
      print("Byte ",i," : ",f[i])

    
if __name__ == "__main__":
  #analyze_dumps_bbb("file4.dump", "file16.dump")
  result = get_dirty_pages("dirty_dump.bin")
  print("List of dirty pages with percentage dirtiness :\n",result)
