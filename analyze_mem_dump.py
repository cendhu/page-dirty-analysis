def analyze_dumps(dump1, dump2):
  f1_bytes = open(dump1, "rb").read()
  f2_bytes = open(dump2, "rb").read()
  f_result = open("dirty_dump.dump", "wb")
  try:
    print(len(f1_bytes))
    for index in range(len(f1_bytes)):
      #print(f1_bytes[index]," ",f2_bytes[index])
      new_int = f1_bytes[index] ^ f2_bytes[index]
      new_byte = bytes(new_int)
      #print(new_int,">>>>>",new_byte)
      f_result.write(new_byte)
  finally:
    f_result.close()

if __name__ == "__main__":
  analyze_dumps("file10.dump", "file52.dump")
