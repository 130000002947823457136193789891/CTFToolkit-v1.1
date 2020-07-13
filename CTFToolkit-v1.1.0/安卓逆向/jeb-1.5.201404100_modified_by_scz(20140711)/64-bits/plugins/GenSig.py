#? name=Signature Generator, shortcut=Ctrl+Shift+S, author=Nicolas Falliere, help=Create binary signatures for library code recognition

from jeb.api import IScript
from jeb.api.dex import DexDalvikInstruction

import hashlib
import os
import re
import string


class GenSig(IScript):

  def run(self, jeb):
    self.jeb = jeb
    self.dex = jeb.getDex()
    self.ui = jeb.getUI()
    self.start()


  def start(self):
    print 'Generating binary signatures...'

    if not self.jeb.isFileLoaded():
      print 'Please load a file'
      return

    if self.jeb.getSoftwareVersion() < '1.3':
      print 'JEB version 1.3+ is required'
      return

    self.verbose = False
    self.libname = None
    self.pattern = None
    self.data = ''
    self.comment = 'JEB signature file'
    self.version = 1
    self.method_count = 0

    # non-interactive mode: optional script arguments can be provided
    args = self.jeb.getScriptArguments()
    if args:
      if len(args) >= 1:
        self.libname = args[0]
      if len(args) >= 2:
        self.pattern = args[1]

    success = self.signFile()
    if success:
      print 'Done, %d methods signed' % self.method_count
    else:
      print 'Error'


  def signFile(self):
    # library name
    if not self.libname:
      deflibname = os.path.splitext(os.path.split(self.jeb.getInputPath())[-1])[0]
      if self.ui:
        self.libname = self.ui.displayQuestionBox('Library name', 'Name for the signature set (recommended format: "name-version")', deflibname)
      else:
        self.libname = raw_input('Enter a name for the signature set (default: %s): ' % deflibname)
      if not self.libname:
        self.libname = deflibname
    print 'Name: %s' % self.libname

    # regex defining what should be signed
    if not self.pattern:
      defpattern = '.*'
      if self.ui:
        self.pattern = self.ui.displayQuestionBox('Mask', 'Methods to be signed (regex)', defpattern)
      else:
        self.pattern = raw_input('Methods to be signed (regex, default: %s): ' % defpattern)
      if not self.pattern:
        self.pattern = defpattern
    print 'Pattern: %s' % self.pattern

    # build the regex
    try:
      self.mask = re.compile(self.pattern)
    except:
      print 'Error: Invalid regular expression'
      return False

    # metadata for the signature file, 'version' and 'libname' are important
    self.record(';comment=%s' % self.comment)
    self.record(';author=%s' % self.jeb.getUserName())
    self.record(';version=%d' % self.version)
    self.record(';libname=%s' % self.libname)

    # hash all methods
    for msig in self.dex.getMethodSignatures(True):
      md = self.dex.getMethodData(msig)
      if not md:
        continue

      code = md.getCodeItem()
      if not code:
        continue

      if not self.mask.match(msig):
        continue

      mhash = GenSig.hashMethod(code)
      if not mhash:
        continue

      m = self.dex.getMethod(md.getMethodIndex())
      name = m.getName()
      proto = self.dex.getPrototype(m.getPrototypeIndex())
      shorty = self.dex.getString(proto.getShortyIndex())
      classfullname = self.dex.getType(m.getClassTypeIndex())
      opcount = code.getInstructionsCount()

      self.record('%s,%s,%s,%d,%s' % (classfullname, name, shorty, opcount, mhash))
      self.method_count += 1

    # save to file
    if self.method_count >= 1:
      # build appropriate filename, do not overwrite existing files
      prefix = self.buildFilename(self.libname)
      path = os.path.join(self.jeb.getSignaturesDirectory(), prefix+'.sig')
      cnt = 1
      while os.path.exists(path):
        filename = '%s_%d.sig' % (prefix, cnt)
        path = os.path.join(self.jeb.getSignaturesDirectory(), filename)
        cnt += 1

      print 'Saving signatures to: %s' % path
      f = open(path, 'w')
      f.write(self.data.encode('utf-8'))
      f.close()

    return True


  def record(self, s):
    self.data += s + '\n'
    if self.verbose:
      print s


  def buildFilename(self, rawname):
    validchars = '-_.() %s%s' % (string.ascii_letters, string.digits)
    r = ''
    for c in rawname:
      if c not in validchars:
        r += '_'
      else:
        r += c
    return r


  # be immune to enum int value changes
  PTID = {
    DexDalvikInstruction.TYPE_REG: 0,
    DexDalvikInstruction.TYPE_IMM: 1,
    DexDalvikInstruction.TYPE_IDX: 2,
    DexDalvikInstruction.TYPE_BRA: 3,
    DexDalvikInstruction.TYPE_RGR: 4}

  @staticmethod
  def hashMethod(code):
    sig = ''

    insns = code.getInstructions()
    for insn in insns:
      token = insn.getMnemonic() + ':'
      # note: array- and switch-data are disregarded
      for param in insn.getParameters():
        pt = param.getType()
        token += '%d,' % GenSig.PTID.get(pt, -1)
        if pt == DexDalvikInstruction.TYPE_IDX:
          token += 'x,'  # disregard pool indexes
        else:
          token += '%d,' % param.getValue()
      token += ' '
      sig += token

    m = hashlib.sha256()
    m.update(sig)
    mhash = m.hexdigest()
    return mhash
