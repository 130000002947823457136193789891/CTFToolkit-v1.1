# JEB script - demo AST API
# Obad, Part 3: Remove useless try-catch blocks after Obad is unreflected
# See www.android-decompiler.com/blog

import sys
import os
import time
from jeb.api import IScript
from jeb.api import EngineOption
from jeb.api.ui import View
from jeb.api.dex import Dex
from jeb.api.ast import TryStm, Compound, Throw



class ObadClean(IScript):

  def run(self, jeb):
    self.jeb = jeb
    self.dex = self.jeb.getDex()

    v = self.jeb.getUI().getView(View.Type.JAVA)
    if not v:
      print 'Switch to the Java view, position the caret somewhere inside the method to be decompiled'
      return

    self.msig = v.getCodePosition().getSignature()
    print 'Cursor: %s' % self.msig
    
    r = jeb.decompile(self.msig, False, False)
    if not r:
      print 'Could not find method'
      return

    m = jeb.getDecompiledMethodTree(self.msig)
    self.revertReflection(m.getBody())


  def revertReflection(self, block):
    i = 0
    while i < block.size():
      stm = block.get(i)
      if isinstance(stm, TryStm):
        if stm.getCatchCount() == 1 and stm.getCatchType(0) == 'Ljava/lang/Throwable;':
          catchb = stm.getCatchBody(0)
          if catchb.size() == 1 and isinstance(catchb.get(0), Throw):
            print 'Removing try/finally'
            tryb = stm.getTryBody()
            block.remove(i)
            self.insertStatements(block, i, tryb)
            continue
      elif isinstance(stm, Compound):
        for b in stm.getBlocks():
          self.revertReflection(b)
      i += 1


  def insertStatements(self, block, index, src):
    j = 0
    while j < src.size():
      block.insert(index, src.get(j))
      index += 1
      j += 1