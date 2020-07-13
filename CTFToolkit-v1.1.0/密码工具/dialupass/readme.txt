


Dialupass v3.50
Copyright (c) 2001 - 2016 Nir Sofer
Web site: http://www.nirsoft.net



Description
===========

This utility enumerates all dialup/VPN entries on your computers, and
displays their logon details: User Name, Password, and Domain. You can
use it to recover a lost password of your Internet connection or VPN.
Dialupass also allows you to save the dialup/VPN list into
text/html/csv/xml file, or copy it to the clipboard.



Known Problems
==============

False Alert Problems: Some Antivirus programs detect Dialupass utility as
infected with Trojan/Virus.



System Requirements
===================

This utility works under Windows 2000, Windows XP, Windows 2003/2008,
Windows Vista, Windows 7, Windows 8, and Windows 10. The passwords are
revealed only if you log on to the computer with administrator
privileges. If you need to recover your dialup passwords from Windows
9x/ME, you can use Dialupass v2.45



Versions History
================




26/07/2016
3.50

* Added support for decrypting dialup/VPN passwords from external drive
  of Windows 10/8/7. ('Advanced Options' window - F9)
* When extracting passwords from external drive - You can now also
  specify the Registry hives folder (instead of Windows directory) and
  the phonebook folder (instead of profiles base folder).


17/09/2014
3.21

* Removed the command-line options that export the passwords to a file
  from the official version. A version of this tool with full
  command-line support will be posted on separated Web page.


24/04/2013
3.20

* Added 'Copy /setpass Command-Line' option (Under the Edit menu). It
  copies to the clipboard the /setpass command-line for all selected
  passwords. You can use this option to easily generate a script to set
  the user name/password/domain for all dialup items on another computer.


22/01/2011
3.16

* Added 'Copy Password' option (Ctrl+P).


27/12/2010
3.15

* Added an option to export the passwords into KeePass csv file (In
  'Save Selected Items'). You can use the created csv file to easily
  import your Web site passwords into KeePass password manager.
* Also Added /skeepass command-line option to export the passwords into
  KeePass csv file.


29/08/2010
3.10

* Added 'Password Strength' column, which calculates the strength of
  the password and displays it as Very Weak, Weak, Medium, Strong, or
  Very Strong.
* Added 'Add Header Line To CSV/Tab-Delimited File' option. When this
  option is turned on, the column names are added as the first line when
  you export to csv or tab-delimited file.


08/07/2010
3.06

* Fixed issue: removed the wrong encoding from the xml string, which
  caused problems to some xml viewers.


07/10/2009
3.05

* Added sorting command-line options.


06/09/2009
3.02

* Added 'Show Items Without User/Password' option.


25/01/2009
3.01

* Dialupass now also locate the phonebook file even when the
  'Application Data' folder is in non-english language.


01/01/2009
3.00

* Dialupass completely rewritten, and the new version contains all the
  current NirSoft standards, including the ability to translate to other
  languages.
* Added support for recovering dialup passwords from external instance
  of Windows 2000/XP/2003. This feature can be useful if you have a dead
  operating system that cannot boot anymore.
* Added support for setting dialup user/password from command-line
  (/setpass)


03/05/2008
2.45

* Fixed bug: Dialupass crashed under Windows Vista.


29/12/2007
2.44

* The configuration is now saved to a file, instead of the Registry
* Under vista, Dialupass now automatically requires to run as
  administrator.


12/09/2004
2.43

* Fixed bug: In previous versions, Dialupass failed to load the user
  name/passwords details if the dial-up item name contained ']' or '['
  characters.


21/07/2004
2.42

* Fixed bug: Dialupass failed to change the user/password details under
  Windows XP.


25/08/2003
2.41

* Fixed bug: In previous version, the user/password details were not
  shown if the dial-up item name contained one or more non-english
  characters. (Windows 2000/XP)
* If the program causes an exception during the password extraction
  process, it won't crash immediately, and it'll allow the user to
  continue to run it.


01/08/2003
2.40

* Added command-line support.
* Option to view the user/password details of all user profiles on the
  system (Only for Windows NT, 2000, and XP)
* Save as vertical html file.


06/07/2003
2.30

* Sort the dialup items by clicking the columns header.
* Change the location of a column by dragging it to a new location.
* All your settings (window size, columns size) are saved, and loaded
  in the next time that you run the Dialupass utility.


05/05/2003
2.20

* View the dial-up passwords of other users in the same computer
  (Windows NT/2000/XP)
* Save the dial-up items in tabular text files.
* Save the dial-up items as HTML file.
* The area code is now shown with the phone number.
* The size of the executable decreased to 30K.


03/03/2003
2.10

* Fixed bug: Passwords saved for all users in Windows XP are now shown
  properly.
* Popup menu.


14/02/2003
2.00

* Added support for Windows 2000/XP
* Completely new user interface.
* Added phone numbers.


12/09/2001
1.00
First release. Only for Windows 95/98/NT.



Using Dialupass
===============

Dialupass is a standalone application, and it doesn't require any
installation process or additional DLLs. Just copy the dialupass.exe to
any folder you want and run it. After you run it, it'll instantly show
all your Dial-Up accounts and their user/password details.
You can also select one or more Dial-Up items (by using Ctrl and Shift
keys), and then save them into text/csv/html/xml file , or copy them into
the clipboard (Ctrl+C).

Dialupass utility also allows you to easily edit the logon details: user
name, password and domain. You can get the editing dialog-box by
double-clicking the item you want to edit.



Command-Line Options
====================



/setpass <Entry Name> <User Name> <Password> <Domain>
Set the user name, password, and domain for the specified dialup entry.

/external <Windows Directory> <Profiles Base Folder>
Load the dialup items from external instance of Windows 2000/XP/2003
operating system. For example:
dialupass.exe /external "j:\windows" "j:\Documents and Settings"

/pbkfile <Phonebook file>
Specifies the phonebook file to load.



Translating Dialupass to other languages
========================================

In order to translate Dialupass to other language, follow the
instructions below:
1. Run Dialupass with /savelangfile parameter:
   Dialupass.exe /savelangfile
   A file named Dialupass_lng.ini will be created in the folder of
   Dialupass utility.
2. Open the created language file in Notepad or in any other text
   editor.
3. Translate all string entries to the desired language. Optionally,
   you can also add your name and/or a link to your Web site.
   (TranslatorName and TranslatorURL values) If you add this information,
   it'll be used in the 'About' window.
4. After you finish the translation, Run Dialupass, and all translated
   strings will be loaded from the language file.
   If you want to run Dialupass without the translation, simply rename
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
