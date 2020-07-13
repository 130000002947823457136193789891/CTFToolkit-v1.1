#include <idc.idc>

// This script is to be used with the 'grep' ida plugin
// It looks for the specified instruction mnemonics and saves all matches

static find_insn(mnem)
{
  auto ea;
  for ( ea=MinEA(); ea != BADADDR; ea=NextHead(ea, BADADDR) )
  {
    if ( GetMnem(ea) == mnem )
      SaveMatch(ea, "");
  }
}