


Remote Desktop PassView v1.02
Copyright (c) 2006 - 2014 Nir Sofer
Web site: http://www.nirsoft.net



Description
===========

Remote Desktop PassView is a small utility that reveals the password
stored by Microsoft Remote Desktop Connection utility inside the .rdp
files.



Versions History
================


* Version 1.02 - Removed the command-line options that export the
  passwords to a file from the official version. A version of this tool
  with full command-line support will be posted on separated Web page.
* Version 1.01 - The configuration is now saved to a file instead of
  the Registry.
* Version 1.00 - First release.



License
=======

This utility is released as freeware. You are allowed to freely
distribute this utility via floppy disk, CD-ROM, Internet, or in any
other way, as long as you don't charge anything for this. If you
distribute this utility, you must include all files in the distribution
package, without any modification !
Be aware that selling this utility as a part of a software package is not
allowed !



Disclaimer
==========

The software is provided "AS IS" without any warranty, either expressed
or implied, including, but not limited to, the implied warranties of
merchantability and fitness for a particular purpose. The author will not
be liable for any special, incidental, consequential or indirect damages
due to loss of data or any other reason.



Using Remote Desktop PassView
=============================

Remote Desktop PassView doesn't require any installation process or
additional DLL files. Just copy the executable (rdpv.exe) to any folder
you like, and run it. After you run rdpv.exe, the main window display the
passwords of .rdp located under your "My Documents" folder. The default
.rdp file (Default.rdp) is usually stored in this location
If you want to recover that password of another .rdp file, just drag the
file from Explorer into the window of Remote Desktop PassView utility or
use the "Open .rdp File" option from the File menu.
Be aware that Remote Desktop PassView can only recover the passwords
created by your current logged on user. It cannot recover the passwords
of .rdp files created by other users.



Translating Remote Desktop PassView To Another Language
=======================================================

Remote Desktop PassView allows you to easily translate all menus,
dialog-boxes, and other strings to other languages.
In order to do that, follow the instructions below:
1. Run Remote Desktop PassView with /savelangfile parameter:
   rdpv.exe /savelangfile
   A file named rdpv_lng.ini will be created in the folder of Remote
   Desktop PassView utility.
2. Open the created language file in Notepad or in any other text
   editor.
3. Translate all menus, dialog-boxes, and string entries to the
   desired language.
4. After you finish the translation, Run Remote Desktop PassView, and
   all translated strings will be loaded from the language file.
   If you want to run Remote Desktop PassView without the translation,
   simply rename the language file, or move it to another folder.



Feedback
========

If you have any problem, suggestion, comment, or you found a bug in my
utility, you can send a message to nirsofer@yahoo.com
