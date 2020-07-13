


PstPassword v1.17
Copyright (c) 2006 - 2014 Nir Sofer
Web site: http://www.nirsoft.net



Description
===========

PstPassword is a small utility that recover lost password of Outlook .PST
(Personal Folders) file.



System Requirements
===================

This utility can recover the PST passwords of Outlook 97, Outlook 2000,
Outlook XP, Outlook 2003, and Outlook 2007. You don't have to install
MS-Outlook in order to use this utility. You only need the original PST
file that you locked with a password.



Versions History
================


* Version 1.17:
  o Removed the command-line options that export the passwords to a
    file from the official version. A version of this tool with full
    command-line support will be posted on separated Web page.

* Version 1.16:
  o Added 'Copy First Password' option (Ctrl+P).

* Version 1.15:
  o Added 'Add Header Line To CSV/Tab-Delimited File' option. When
    this option is turned on, the column names are added as the first
    line when you export to csv or tab-delimited file.
  o You can now send the pst passwords list to stdout by specifying
    an empty filename ("") in the command-line of all save parameters.
    For example: PstPassword.exe /stab "" >> c:\temp\passwords.txt

* Version 1.12:
  o Added /pstfiles command-line option.

* Version 1.11:
  o Fixed bug: The dates displayed in system locale format, instead
    of user locale.

* Version 1.10:
  o Added documentation to save command-line options.
  o Added new command-line option: /pstpath
  o Added option to save as comma-delimited (.csv) text file.
  o Fixed bug: The main window lost the focus when the user switched
    to another application and then returned back to PstPassword.

* Version 1.02 - The configuration is now saved to a file instead of
  the Registry.
* Version 1.01 - New option: Get More Passwords - Displays 100
  additional passwords for the selected pst file.
* Version 1.00 - First release.



Password Encryption in PST File
===============================

The password encryption in the PST file is very weak, and for each
password-protected PST file, there are many passwords that can open it.
PstPassword provides 3 different passwords for each password-protected
PST file. It's possible that one of them will be the origianl password
that you typed, and it's also possible that none of these passwords will
be identical to the original one. However, all 3 passwords provided by
PstPassword will open the PST file without problems.
For more interesting facts about the PST password encryption, click here.



Using PstPassword
=================

PstPassword doesn't require any installation process or additional dll
files. In order to start using it, just run the executable file,
PstPassword.exe
After you run PstPassword, the main window displays the list of all PST
files of the current logged on user (Under Documents and Settings\User
Name\Local Settings\Application Data\Microsoft\Outlook). For each
password-protected PST file, PstPassword provide 3 alternative passwords
that will open the PST file. If the PST is not protected by a password,
the 3 password columns remain empty, and the CRC value column is
0x00000000.
If you want to recover a password of PST file that doesn't appear in the
default list, you can press F7 and select the desired PST file, or simply
drag the PST file from Explorer window into the main window of
PstPassword.
If from some reason PstPassword fails to read a PST file, an error
message is displayed under the error column, and the item is painted with
pink color.



Command-Line Options
====================



/stext <Filename>
Save the list of PST passwords into a regular text file.

/stab <Filename>
Save the list of PST passwords into a tab-delimited text file.

/scomma <Filename>
Save the list of PST passwords into a comma-delimited text file.

/stabular <Filename>
Save the list of PST passwords into a tabular text file.

/shtml <Filename>
Save the list of PST passwords into HTML file (Horizontal).

/sverhtml <Filename>
Save the list of PST passwords into HTML file (Vertical).

/sxml <Filename>
Save the list of PST passwords to XML file.

/pstpath <Folder>
Specify the folder that contains the PST files. If you don't specify this
parameter, the default Outlook path is used.

/pstfiles <PST File 1> <PST File 2>...
Specify one or more pst files to load.

Examples:
PstPassword.exe /stab "c:\temp\pass.txt"
PstPassword.exe /stab "c:\temp\pass.txt" /pstpath "c:\temp\pst-files"
PstPassword.exe /scomma "c:\temp\pass.txt" /pstfiles
"c:\temp\pst-files\pst1.pst" "c:\temp\pst-files\pst2.pst"
"c:\temp\pst-files\pst3.pst"



Translating PstPassword To Another Language
===========================================

PstPassword allows you to easily translate all menus, dialog-boxes, and
other strings to other languages.
In order to do that, follow the instructions below:
1. Run PstPassword with /savelangfile parameter:
   PstPassword.exe /savelangfile
   A file named PstPassword_lng.ini will be created in the folder of
   PstPassword utility.
2. Open the created language file in Notepad or in any other text
   editor.
3. Translate all menus, dialog-boxes, and string entries to the
   desired language.
4. After you finish the translation, Run PstPassword, and all
   translated strings will be loaded from the language file.
   If you want to run PstPassword without the translation, simply rename
   the language file, or move it to another folder.



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
