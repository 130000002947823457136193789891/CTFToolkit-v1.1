#// The format of this file is described in api_kernel32.idc

#///func=MessageBoxA entry=messagebox purge=0x10
def messagebox():
  param2 = BochsGetParam(2)
  Message("[Python] MessageBoxA() has been called: %x %s\n" % (param2, GetString(param2, -1, ASCSTR_C)))
  SetRegValue(1,"eax")
  # continue execution
  return 0
