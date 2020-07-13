#? name=Sample Python Plugin, help=This Python script is a JEB plugin

from jeb.api import IScript


class SamplePluginPython(IScript):

  def run(self, jeb):
    jebver = jeb.getSoftwareVersion()
    apiver = jeb.getApiVersion()
    message = 'This is a sample plugin.\n\nJEB version: %s\nAPI version: %s' % (jebver, apiver)

    ui = jeb.getUI()
    if ui:
      ui.displayMessageBox('Sample Plugin', message, ui.IconType.INFORMATION, ui.ButtonGroupType.OK)
    else:
      print message
