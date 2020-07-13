


OperaPassView v1.10
Copyright (c) 2010 - 2013 Nir Sofer
Web site: http://www.nirsoft.net



Description
===========

OperaPassView is a small password recovery tool that decrypts the content
of the Opera Web browser password file (wand.dat) and displays the list
of all Web site passwords stored in this file. You can easily select one
or more passwords in the OperaPassView window, and then copy the
passwords list to the clipboard and save it into text/html/csv/xml file.



System Requirements
===================

This utility works on any version of Windows, starting from Windows 2000
and up to Windows 7/2008. You can use this utility even if Opera Web
browser is not installed on your system, as long as you have the wand.dat
filename.



Known Limitations
=================


* Currently, OperaPassView cannot decrypt the passwords and they are
  encrypted by using the master password.



Versions History
================


* Version 1.10:
  o Fixed to detect properly the passwords of login.live.com and
    probably other Web sites.
  o Added /RawExport command-line option to export Opera wand file
    into a raw text file (without detecting which fields are the user
    names and passwords). This option is useful when OperaPassView fails
    to detect the user name / password field properly and displays other
    fields instead.
  o Added /LoadWand command-line option to specify the desired wand
    file to load.

* Version 1.05:
  o Added an option to export the passwords into KeePass csv file (In
    'Save Selected Items'). You can use the created csv file to easily
    import your Web site passwords into KeePass password manager.
  o Added 'Remember this file in the next time that you use
    OperaPassView' in the Advanced Options window.
  o Added documentation for command-line options.

* Version 1.02:
  o Added 'Password Strength' column, which calculates the strength
    of the password and displays it as Very Weak, Weak, Medium, Strong,
    or Very Strong.

* Version 1.01:
  o Fixed bug: OperaPassView failed to work with large wand.dat files.

* Version 1.00: First release.



Using OperaPassView
===================

OperaPassView doesn't require any installation process or additional dll
files. In order to start using it, simply run the executable file -
OperaPassView.exe
After you run OperaPassView, it automatically tries to locate the
wand.dat of the current logged-on user and display all Web site passwords
stored in this file. You can also manually choose the desired wand.dat
filename by using the 'Advanced Options' window (F8) or simply by
dragging the wand.dat filename from Explorer into the main window of
OperaPassView.

When OperaPassView displays the passwords list, you can select one or
more of these passwords and then copy them to the clipboard (Ctrl+C) or
use the save option (Ctrl+S) for saving them into html/xml/csv/text file.



Command-Line Options
====================



/RawExport <Filename>
Export all data stored inside the Opera wand file into a raw text file.

/LoadWand <Filename>
Specifies the wand.dat file to load.

/stext <Filename>
Save the list of Opera passwords into a regular text file.

/stab <Filename>
Save the list of Opera passwords into a tab-delimited text file.

/scomma <Filename>
Save the list of Opera passwords into a comma-delimited text file (csv).

/stabular <Filename>
Save the list of Opera passwords into a tabular text file.

/shtml <Filename>
Save the list of Opera passwords into HTML file (Horizontal).

/sverhtml <Filename>
Save the list of Opera passwords into HTML file (Vertical).

/sxml <Filename>
Save the list of Opera passwords into XML file.

/skeepass <Filename>
Save the list of Opera passwords into KeePass csv file.



Translating OperaPassView to other languages
============================================

In order to translate OperaPassView to other language, follow the
instructions below:
1. Run OperaPassView with /savelangfile parameter:
   OperaPassView.exe /savelangfile
   A file named OperaPassView_lng.ini will be created in the folder of
   OperaPassView utility.
2. Open the created language file in Notepad or in any other text
   editor.
3. Translate all string entries to the desired language. Optionally,
   you can also add your name and/or a link to your Web site.
   (TranslatorName and TranslatorURL values) If you add this information,
   it'll be used in the 'About' window.
4. After you finish the translation, Run OperaPassView, and all
   translated strings will be loaded from the language file.
   If you want to run OperaPassView without the translation, simply
   rename the language file, or move it to another folder.



License
=======

This utility is released as freeware. You are allowed to freely
distribute this utility via floppy disk, CD-ROM, Internet, or in any
other way, as long as you don't charge anything for this. If you
distribute this utility, you must include all files in the distribution
package, without any modification !



Disclaimer
==========

The software is provided "AS IS" without any warranty, either expressed
or implied, including, but not limited to, the implied warranties of
merchantability and fitness for a particular purpose. The author will not
be liable for any special, incidental, consequential or indirect damages
due to loss of data or any other reason.



Feedback
========

If you have any problem, suggestion, comment, or you found a bug in my
utility, you can send a message to nirsofer@yahoo.com
