#? name=Jump to an Activity, shortcut=Ctrl+Shift+J, help=position the caret on the Activity name in the Manifest, and fire the plugin to jump to the corresponding Activity code

from jeb.api import IScript
from jeb.api.ui import View
from jeb.api.ui import CodePosition


class JumpToActivity(IScript):

  def run(self, jeb):

    # basic requirements
    ui = jeb.getUI()
    if not ui:
      return

    if jeb.getApiVersion() < 2:
      print 'Please upgrade to JEB 1.3'
      return

    ui.focusView(View.Type.MANIFEST)
    v = ui.getView(View.Type.MANIFEST)
    if not v:
      print 'No Manifest'
      return

    # whole copy of the Manifest
    text = v.getText()

    # retrieve the package name
    pname = ''
    pos = text.find('package="')
    if pos >= 0:
      pos += 9
      pos1 = text.find('"', pos)
      if pos1 >= 0:
        pname = text[pos:pos1]

    # the Activity name should be the on-caret item
    aname = v.getActiveItem()
    if not aname:
      print 'Please position the caret on the Activity name'
      return

    # absolute class classname
    if aname.startswith('.'):
      if not pname:
        print 'Package name not found'
        return
      aname = pname + aname

    ui.focusView(View.Type.ASSEMBLY)
    a = ui.getView(View.Type.ASSEMBLY)
    if not a:
      print 'No Assembly view'
      return

    # internal class name
    classname = 'L' + aname.replace('.', '/') + ';'
    if not a.setCodePosition(CodePosition(classname)):
      print 'Class not found: '+aname
      ui.focusView(View.Type.MANIFEST)