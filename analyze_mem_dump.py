def analyze_dumps(dump1, dump2):
  f1_bytes = open(dump1, "rb").read()
  f2_bytes = open(dump2, "rb").read()
  f_bin = open("dirty_dump.bin", "wb")
  f_dec = open("dirty_dump.dec","w")
  try:
    print(len(f1_bytes))
    for index in range(len(f1_bytes)):
      #if index%10000000 == 0:
      print(f1_bytes[index]," ",f2_bytes[index])
      new_int = f1_bytes[index] ^ f2_bytes[index]
      new_byte = bytes(new_int)
      new_binary = bin(new_int)[2:]
      #if index%10000000 == 0:
      print(new_int,">>>>>",new_byte)
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
      #int1 = int.from_bytes(byte1)
      #int2 = int.from_bytes(byte2)
      byte1[i] = byte1[i] ^ byte2[i]
      #new_byte = bytes(new_int)
    f_bin.write(byte1)
  finally:
    f_bin.close()
    f1.close()
    f2.close()


if __name__ == "__main__":
  analyze_dumps_bbb("file4.dump", "file16.dump")
