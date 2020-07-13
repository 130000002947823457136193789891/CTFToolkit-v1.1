# Sample JEB script (UI:yes, Automation:yes)
# Decompile all classes of the input file
# Classes are decompiled to "_decompiled"


import os

from jeb.api import IScript
from jeb.api import EngineOption


class JEBDecompileAll(IScript):

  def run(self, jeb):
    self.jeb = jeb
    self.dex = jeb.getDex()
    if not self.dex:
      print 'Error! Please provide an input file.'
      self.jeb.exit()
    
    outdir = self.jeb.getInputPath() + '_decompiled'
    self.decompileAllClasses(outdir)
    print 'Done.'

  def decompileAllClasses(self, outdir):
    # make sure try/catch blocks are processed
    self.jeb.setEngineOption(EngineOption.DECOMP_PARSE_TRYCATCHES, 'true')

    for csig in self.dex.getClassSignatures(True):
      print 'Decompiling class: %s' % csig

      # do not create separate extra files for inner classes
      # warning! not a robust heuristics at all
      if csig.find('$') >= 0:
        continue

      subpath = csig[1:len(csig)-1] + '.java'
      dirname = subpath[:subpath.rfind('/') + 1]

      dirpath = os.path.join(outdir, dirname)
      if not os.path.exists(dirpath):
        os.makedirs(dirpath)

      dec = self.jeb.decompileClass(csig)
      if not dec:
        dec = '// Decompilation error'
      print 'Decompiled: '+csig
      filepath = os.path.join(outdir, subpath)
      f = open(filepath, 'w')
      f.write('// Decompiled by JEB v%s\n\n' % self.jeb.getSoftwareVersion())
      f.write(dec.encode('utf-8'))
      f.close()