#include <idc.idc>

// The format of this file is described in api_kernel32.idc

///func=MessageBoxA entry=messagebox purge=0x10
static messagebox()
{
  auto param2;

  param2 = BochsGetParam(2);

  Message("MessageBoxA() has been called: %s\n", GetString(param2, -1, ASCSTR_C));

  eax = 1;

  // Continue execution
  return 0;
}
