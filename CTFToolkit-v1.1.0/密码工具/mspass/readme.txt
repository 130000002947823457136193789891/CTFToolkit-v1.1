


MessenPass v1.43
Copyright (c) 2004 - 2014 Nir Sofer
Web site: http://www.nirsoft.net



Description
===========

MessenPass is a password recovery tool that reveals the passwords of the
following instant messenger applications:
* MSN Messenger
* Windows Messenger (In Windows XP)
* Windows Live Messenger (In Windows XP/Vista/7)
* Yahoo Messenger (Versions 5.x and 6.x)
* Google Talk
* ICQ Lite 4.x/5.x/2003
* AOL Instant Messenger v4.6 or below, AIM 6.x, and AIM Pro.
* Trillian
* Trillian Astra
* Miranda
* GAIM/Pidgin
* MySpace IM
* PaltalkScene
* Digsby
MessenPass can only be used to recover the passwords for the current
logged-on user on your local computer, and it only works if you chose the
remember your password in one of the above programs. You cannot use this
utility for grabbing the passwords of other users.



Known Problems
==============

False Alert Problems: Some Antivirus programs detect MessenPass utility
as infected with Trojan/Virus. Click here to read more about false alerts
in Antivirus programs



Send donation to NirSoft
========================

MessenPass is a password recovery tool that you can use freely without
paying any fee. However, I invested many hours of my life for developing
and maintaining this utility and I pay monthly fee for hosting
nirsoft.net Web site.
If this utility helped you to recover your lost password, and you think
that this software is good enough for paying it, you are welcomed to
donate some money through PayPal service. You can donate by using the
following donation link: http://www.nirsoft.net/donate.html.



Versions History
================


* Version 1.43:
  o Removed the command-line options that export the passwords to a
    file from the official version. A version of this tool with full
    command-line support will be posted on separated Web page.

* Version 1.42:
  o Added 'Mark Odd/Even Rows' option, under the View menu. When it's
    turned on, the odd and even rows are displayed in different color, to
    make it easier to read a single line.

* Version 1.41:
  o Added 'Copy Password' option (Ctrl+P).

* Version 1.40:
  o Added an option to export the passwords into KeePass csv file (In
    'Save Selected Items'). You can use the created csv file to easily
    import your messenger passwords into KeePass password manager.
  o Added 'Add Header Line To CSV/Tab-Delimited File' option. When
    this option is turned on, the column names are added as the first
    line when you export to csv or tab-delimited file.
  o You can now send the email passwords list to stdout by specifying
    an empty filename ("") in the command-line of all save parameters.
    For example: mspass.exe /stab "" >> c:\temp\passwords.txt

* Version 1.35 - Added 'Password Strength' column, which calculates the
  strength of the password and displays it as Very Weak, Weak, Medium,
  Strong, or Very Strong.
* Version 1.30 - Fixed issue: MessenPass created a file named '1.bin'
  under e:\temp if this folder was existed. This file was created for
  debugging purposes but accidently remained in the release version too.
* Version 1.29 - Fixed MessenPass to work with the latest version of
  Miranda.
* Version 1.28 - Fixed a crash problem with Application Compatibility
  Engine on Windows 7/Vista.
* Version 1.27 - Added sorting command-line options.
* Version 1.26 - Added AutoComplete support for 'Select Folders'
  dialog-box.
* Version 1.25 - Added support for Trillian Astra.
* Version 1.24 - Added support for Digsby.
* Version 1.23 - Fixed bug: Exception window appeared when starting
  MessenPass in some systems.
* Version 1.22 - Added support for imvu.com passwords stored by Firefox
  and IE7.
* Version 1.21 - Added support for ebuddy.com and Google Talk passwords
  stored by Firefox.
* Version 1.20 - Added support for Paltalk.
* Version 1.18 - Added support for saving as comma-delimited file.
* Version 1.17 - Added support for MySpace IM.
* Version 1.16 - Added support for Google Talk password, if it's stored
  by Google Desktop.
* Version 1.15 - The configuration is now saved to a file instead of
  the Registry.
* Version 1.14 - Added support for AIM 6.x and AIM pro.
* Version 1.13 - Windows Live Messenger passwords are now shown under
  Vista even without admin rights.
* Version 1.12 - Fixed bug: Pidgin passwords were not shown when using
  the save command-line options.
* Version 1.11 - Added support for Pidgin (Successor of GAIM)
* Version 1.10 - Added support for Windows Live Messenger under Vista.
  (Requires to run as admin)
* Version 1.08 - Added support for Google Talk.
* Version 1.07 - Added support for Windows Live Messenger and for Yahoo
  accounts in Miranda.
* Version 1.06 - Added support for SIP and Exchange Instant Messaging
  accounts on Windows Messenger.
* Version 1.05 - Added support for newer versions of Miranda.
* Version 1.04 - Added support for MSN Messenger v7.5 (Multiple
  accounts)
* Version 1.03 - Added command-line support.
* Version 1.02 - Added support Versions 5.x of Yahoo Messenger.
* Version 1.01 - Added support for ICQ Lite 4.x/2003
* Version 1.00 - First release.



Installing MessenPass
=====================

MessenPass can be used without any installation process, simply by
running the executable file (mspass.exe) from the zip file.
If you want to install MessenPass with automatic creation of program
group icons and uninstall support, download and run the self-install
executable file.



Using MessenPass
================

When you run MessenPass, it automatically detects the Instant Messenger
applications installed on your computer, decrypts the passwords they
store, and displays all user name/password pairs that it found in the
main window of MessenPass. If from some reason, MessenPass fails to
locate the installed Instant Messenger application, you can try to
manually select the right folder of your IM application by using 'Select
Folders' option (from the File menu).

On the main window of MessenPass, you can select one or more password
items, and then copy them to the clipboard in tab-delimited format (you
can paste this format into Excel or Open-Office Spreadsheet), or save
them into text/html files.



Command-Line Options
====================

You can also save the passwords of your Instant Messenger applications
without displaying any user interface, by using the following
command-line options:

/stext <Filename>
Save all instant messenger passwords into a regular text file.

/stab <Filename>
Save all instant messenger passwords into a tab-delimited text file.

/scomma <Filename>
Save all instant messenger passwords into a comma-delimited text file.

/stabular <Filename>
Save all instant messenger passwords into a tabular text file.

/shtml <Filename>
Save all instant messenger passwords into HTML file.

/sverhtml <Filename>
Save all instant messenger passwords into HTML file. (vertical)

/sxml <Filename>
Save all instant messenger passwords into XML file.

/skeepass <Filename>
Save all instant messenger passwords into KeePass csv file.

/sort <column>
This command-line option can be used with other save options for sorting
by the desired column. If you don't specify this option, the list is
sorted according to the last sort that you made from the user interface.
The <column> parameter can specify the column index (0 for the first
column, 1 for the second column, and so on) or the name of the column,
like "Software" and "Protocol". You can specify the '~' prefix character
(e.g: "~User") if you want to sort in descending order. You can put
multiple /sort in the command-line if you want to sort by multiple
columns.

Examples:
mspass.exe /shtml "f:\temp\mspass.html" /sort 2 /sort ~1
mspass.exe /shtml "f:\temp\mspass.html" /sort "Protocol" /sort "User"

/nosort
When you specify this command-line option, the list will be saved without
any sorting.



Translating MessenPass to other languages
=========================================

MessenPass allows you to easily translate all menus, dialog-boxes, and
other strings to other languages.
In order to do that, follow the instructions below:
1. Run MessenPass with /savelangfile parameter:
   mspass.exe /savelangfile
   A file named mspass_lng.ini will be created in the folder of
   MessenPass utility.
2. Open the created language file in Notepad or in any other text
   editor.
3. Translate all menus, dialog-boxes, and string entries to the
   desired language.
4. After you finish the translation, Run MessenPass, and all
   translated strings will be loaded from the language file.
   If you want to run MessenPass without the translation, simply rename
   the language file, or move it to another folder.



License
=======

This utility is released as freeware. You are allowed to freely use it at
your home or in your company. However, you are not allowed to make profit
from this software or to charge your customers for recovering their
passwords with this software, unless you got a permission from the
software author.
You are also allowed to freely distribute this utility via floppy disk,
CD-ROM, Internet, or in any other way, as long as you don't charge
anything for this. If you distribute this utility, you must include all
files in the distribution package, without any modification !



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
