


PasswordFox v1.57
Copyright (c) 2008 - 2016 Nir Sofer
Web site: http://www.nirsoft.net



Description
===========

PasswordFox is a small password recovery tool that allows you to view the
user names and passwords stored by Mozilla Firefox Web browser. By
default, PasswordFox displays the passwords stored in your current
profile, but you can easily select to watch the passwords of any other
Firefox profile. For each password entry, the following information is
displayed: Record Index, Web Site, User Name, Password, User Name Field,
Password Field, and the Signons filename.



System Requirements
===================

This utility works under Windows 2000, Windows XP, Windows Server 2003,
Windows Vista, Windows 7, Windows 8, and Windows 10. Firefox should also
be installed on your system in order to use this utility.
Be aware that for Firefox 64-bit, you must use the 64-bit version of this
tool and for Firefox 32-bit, you must use the 32-bit version of this tool.



Versions History
================


* Version 1.57
  o On 64-bit systems, PasswordFox now displays a note about using
    the correct 32-bit/64-bit version if it fails to load the decryption
    library of Firefox.

* Version 1.56
  o PasswordFox now automatically detects the portable version of
    Firefox that is currently running in the background, if it cannot
    find any other installation of Firefox.

* Version 1.55
  o Added 'Show Old Passwords' option. When it's turned on,
    PasswordFox displays passwords stored by old versions of Firefox.

* Version 1.50
  o Added new columns: Created Time, Last Time Used, Password Change
    Time, Password Use Count.
  o Removed the export command-line options from the official
    release, in order to decrease the rate of false Virus alerts.

* Version 1.40
  o Added support for Firefox 32 (logins.json).

* Version 1.37
  o Added PasswordFox 64-bit to work with Waterfox Web browser. (For
    Firefox Web browser, you should continue using the 32-bit version of
    PasswordFox, even if your system is 64-bit)

* Version 1.36
  o Fixed to work with Firefox 22.

* Version 1.35
  o Fixed bug: PasswordFox failed to work with master password
    containing non-English characters.
  o Added 'Mark Odd/Even Rows' option, under the View menu. When it's
    turned on, the odd and even rows are displayed in different color, to
    make it easier to read a single line.
  o Fixed issue: Dialog-boxes opened in the wrong monitor, on
    multi-monitors system.

* Version 1.32
  o Fixed the tab order in the 'Select Folders' dialog-box.

* Version 1.31
  o Fixed bug: PasswordFox failed to get the passwords if the profile
    path of Firefox contained non-English characters.
  o Removed the UPX compression to avoid from false positives of
    Windows Defender and other Antivirus programs.

* Version 1.30
  o Fixed memory leak that occurred on every refresh.
  o Added support for Firefox 4 (Beta).
  o Fixed a problem with /installfolder command-line parameter.
  o Added 'Firefox Version' column.

* Version 1.26
  o Added an option to export the passwords into KeePass csv file (In
    'Save Selected Items'). You can use the created csv file to easily
    import your Web site passwords into KeePass password manager.
  o Fixed issue: removed the wrong encoding from the xml string,
    which caused problems to some xml viewers.

* Version 1.25
  o Added 'Password Strength' column, which calculates the strength
    of the password and displays it as Very Weak, Weak, Medium, Strong,
    or Very Strong.
  o Added 'Add Header Line To CSV/Tab-Delimited File' option. When
    this option is turned on, the column names are added as the first
    line when you export to csv or tab-delimited file.
  o Removed the error messages when using PasswordFox from
    command-line

* Version 1.20
  o Fixed bug: PasswordFox failed to display properly non-English
    characters in user name/password data.
  o Added 'HTTP Realm' column. (Displayed only for some HTTP
    password-protected Web sites and only on Firefox 3.x or greater)

* Version 1.15
  o Added support for reading the signons.sqlite in new versions of
    Firefox.

* Version 1.12:
  o Added accelerator key for 'Select Folder' option.
  o Added sorting from command-line.

* Version 1.11:
  o Added new option in 'Select Folders' dialog-box: Remember the
    folder settings in the next time that you use PasswordFox.

* Version 1.10:
  o Added support for specifying the master password (in the 'Select
    Folders' dialog-box or from command-line).

* Version 1.05:
  o Added support for selecting the right Firefox installation folder.
  o Added /installfolder command-line option.
  o Added AutoComplete feature in Select Folders dialog-box.



* Version 1.00 - First release.



Using PasswordFox
=================

PasswordFox doesn't require any installation process or additional DLL
files. However, Firefox browser must be installed on your computer in
order allow PasswordFox to grab the passwords list.
In order to start using PasswordFox, simply run the executable file -
PasswordFox.exe
After running it, the main window will display all your passwords list
for the last profile that you used. If PasswordFox chose the wrong
profile folder, you can use the 'Select Profile Folder' option to choose
the right one.



Command-Line Options
====================



/profile <Folder>
Choose the desired Firefox profile folder.

/installfolder <Folder>
Choose the desired Firefox installation folder.

/master <Password>
Specify the master password.



Translating PasswordFox to other languages
==========================================

In order to translate PasswordFox to other language, follow the
instructions below:
1. Run PasswordFox with /savelangfile parameter:
   PasswordFox.exe /savelangfile
   A file named PasswordFox_lng.ini will be created in the folder of
   PasswordFox utility.
2. Open the created language file in Notepad or in any other text
   editor.
3. Translate all string entries to the desired language. Optionally,
   you can also add your name and/or a link to your Web site.
   (TranslatorName and TranslatorURL values) If you add this information,
   it'll be used in the 'About' window.
4. After you finish the translation, Run PasswordFox, and all
   translated strings will be loaded from the language file.
   If you want to run PasswordFox without the translation, simply rename
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
