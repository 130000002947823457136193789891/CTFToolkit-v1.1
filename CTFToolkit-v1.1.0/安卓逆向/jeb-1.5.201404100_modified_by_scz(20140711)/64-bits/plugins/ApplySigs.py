#? name=Library Recognition, author=Nicolas Falliere, help=Apply binary signatures for library code recognition

from jeb.api import IScript
from jeb.api.dex import Dex
from jeb.api.dex import DexDalvikInstruction
from jeb.api.ui import View

import hashlib
import os
import string

from GenSig import GenSig


class ApplySigs(IScript):

  def run(self, jeb):
    self.jeb = jeb
    self.dex = jeb.getDex()
    self.ui = jeb.getUI()
    success = self.start()


  def start(self):
    print 'Applying binary signatures...'

    if not self.jeb.isFileLoaded():
      print 'Please load a file'
      return

    if self.jeb.getSoftwareVersion() < '1.3':
      print 'JEB version 1.3+ is required'
      return

    self.all = {}   # method hashes
    self.allc = {}  # class hashes

    self.matchcount_total = 0     # number of new methods matched
    self.matchcount_new = 0       # number of new methods matched
    self.matchcount_per_lib = {}  # library name -> number of methods matched within that library

    self.loadAllSignatures()
    self.applySignatures()

    if self.matchcount_new and self.ui:
      self.ui.getView(View.Type.ASSEMBLY).refresh()

    print '%d new signatures' % self.matchcount_new
    if self.matchcount_total > 0:
      print 'All signatures:'
      a = self.matchcount_per_lib.items()
      a.sort(lambda x, y: -cmp(x[1], y[1]))
      for libname, cnt in a:
        print '- %s: %d' % (libname, cnt)

    print 'Done'


  def loadAllSignatures(self):
    base = self.jeb.getSignaturesDirectory()
    for filename in os.listdir(base):
      if filename.lower().endswith('.sig'):
        path = os.path.join(base, filename)
        if os.path.isfile(path):
          self.loadSignatures(path)


  def loadSignatures(self, path):
    # default
    version = 0
    libname = 'Unknown library code'

    print 'Loading file: %s' % path
    f = open(path)
    lines = f.readlines()
    f.close()

    # load method signatures
    def checkMarker(line, marker):
      data = None
      if line.startswith(marker+'='):
        data = line[len(marker)+1:].strip()
      return data

    signatures = []
    for line in lines:
      line = line.decode('utf-8').strip()
      if not line:
        continue

      # config/metadata
      if line.startswith(';'):
        line = line[1:]

        data = checkMarker(line, 'version')
        if data:
          try:
            version = int(data)
          except:
            print 'Warning: Invalid version in signature file: %s' % data
            break

        data = checkMarker(line, 'libname')
        if data:
          libname = data

      # signature data
      else:
        if version != 1:
          print 'Warning: Unsupported version in signature file: %s' % version
          break

        #cname, mname, shorty, opcount, mhash
        tokens = line.split(',')
        if len(tokens) != 5:
          print 'Warning: Invalid signature line: %s' % line
          continue

        signatures.append(tokens)

    # sort method signatures by ascending cname
    signatures.sort()

    # build class signatures, derived from method signatures
    def storeClassHash(chash, cname, libname):
      if chash != 1L:
        if chash not in self.allc:
          self.allc[chash] = []
        self.allc[chash].append((libname, cname))
    chash, cname0 = 1L, None
    for cname, mname, shorty, opcount, mhash in signatures:
      if cname != cname0:
        storeClassHash(chash, cname0, libname)
        chash, cname0 = 1L, cname
      chash *= long(mhash[0:16], 16)
    storeClassHash(chash, cname0, libname)

    # store method signatures
    def storeMethodHash(mhash, cname, mname, libname):
      if mhash not in self.all:
        self.all[mhash] = []
      self.all[mhash].append((libname, cname, mname))
    for cname, mname, shorty, opcount, mhash in signatures:
      storeMethodHash(mhash, cname, mname, libname)

    # note: recommended libname format is: 'name-version'
    # sort by descending library name: more recent libraries will be picked first
    for key in self.allc:
      self.allc[key].sort(lambda x, y: -cmp(x[0], y[0]))
    for key in self.all:
      self.all[key].sort(lambda x, y: -cmp(x[0], y[0]))


  # do not match small routines or small classes
  MIN_OPCODE_LENGTH = 8

  def applySignatures(self):
    # class hashes for the current file, built on the fly
    # maps a type index to a tuple (class hash, total number of opcodes)
    chashes = {}

    # method matching
    for msig in self.dex.getMethodSignatures(True):
      md = self.dex.getMethodData(msig)
      if not md:
        continue

      code = md.getCodeItem()
      if not code:
        continue

      mhash = GenSig.hashMethod(code)
      if not mhash:
        continue

      # update associated class signature
      m = self.dex.getMethod(md.getMethodIndex())
      cti = m.getClassTypeIndex()
      chash_h, chash_n = chashes.get(cti, (1L, 0))
      chash_h *= long(mhash[0:16], 16)
      chash_n += code.getInstructionsCount()
      chashes[cti] = (chash_h, chash_n)

      # do not attempt method matching if the method is too small
      if code.getInstructionsCount() >= ApplySigs.MIN_OPCODE_LENGTH:
        for libname1, cname1, mname1 in self.all.get(mhash, []):
          # process the first match
          # (do not check the shorty, a perfect hash match is enough)
          self.matchcount_total += 1

          # mark the method as a library method
          f = md.getUserFlags()
          if (f & Dex.FLAG_LIBRARY) == 0:
            md.setUserFlags(f | Dex.FLAG_LIBRARY)
            self.matchcount_new += 1

          if libname1 not in self.matchcount_per_lib:
            self.matchcount_per_lib[libname1] = 0
          self.matchcount_per_lib[libname1] += 1

          # TODO: could also rename the class
          # TODO: add as a method comment: library name, method name
          self.jeb.renameMethod(msig, mname1)

          # disregard potential other matches
          break

    # class matching, not as accurate, but useful for classes having
    # lots of small methods (therefore, unmatched methods)
    for i in range(self.dex.getClassCount()):
      c = self.dex.getClass(i)
      cti = c.getClasstypeIndex()
      chash_h, chash_n = chashes.get(cti, (1L, 0))

      # do not attempt class matching if the class is 'too small'
      if chash_n >= ApplySigs.MIN_OPCODE_LENGTH:
        for libname1, cname1 in self.allc.get(chash_h, []):
          # process the first match
          c.setUserFlags(c.getUserFlags() | Dex.FLAG_LIBRARY_EXT)

          # disregard potential other matches
          break
