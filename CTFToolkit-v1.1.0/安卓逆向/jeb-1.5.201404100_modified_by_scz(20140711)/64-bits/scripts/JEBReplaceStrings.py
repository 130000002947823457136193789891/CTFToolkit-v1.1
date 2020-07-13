# Sample JEB script (UI:yes, Automation:yes)
# Replace code strings by the string 'foobar'
# This script shows how to navigate the DEX file
# and how to modify strings in the string pool


import os

from jeb.api import IScript
from jeb.api import EngineOption


class JEBReplaceStrings(IScript):

  def run(self, jeb):
    self.jeb = jeb
    self.dex = jeb.getDex()
    if not self.dex:
      print 'Error! Please provide an input file.'
      sef.jeb.exit()

    for msig in self.dex.getMethodSignatures(True):
      #print msig

      md = self.dex.getMethodData(msig)
      if not md:
        continue

      code = md.getCodeItem()
      if not code:
        continue

      for insn in code.getInstructions():
        if not insn.getMnemonic() in ('const-string', 'const-string/jumbo'):
          continue

        stringindex = insn.getParameters()[1].getValue()
        s = self.dex.getString(stringindex)
        if s:
          s2 = self.modifyString(s)
          if s2 and s2 != s:
            self.dex.setString(stringindex, s2)

  def modifyString(self, s):
    # totally useless: alphanumeric string are replaced by 'foobar'
    # could be the base script for something more useful, like
    # string language identification and translation into English
    if not s.isalnum():
      return None
    return 'foobar'