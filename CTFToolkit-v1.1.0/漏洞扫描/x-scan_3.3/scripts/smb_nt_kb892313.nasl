#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(18085);
 script_bugtraq_id (13607);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "DRM Update in Windows Media Player may facilitate spyware infections (892313)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version Windows Media Player 9 or Windows Media 
Player 10 which contains a vulnerability which may allow an attacker to infect 
the remote host with spyware.

An attacker may exploit this flaw by crafting malformed WMP files which will
cause Windows Media Player to redirect the users to a rogue website when 
attempting to acquire a license to read the file.

Solution : http://support.microsoft.com/kb/892313/
See also : http://www.benedelman.org/news/010205-1.html
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Media Player";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsMediaPlayer");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");

port = get_kb_item("SMB/transport");
if(!port) port = 139;

if ( hotfix_check_sp(xp:3, win2k:5, win2003:2) <= 0 ) exit(0);

version = get_kb_item("SMB/WindowsMediaPlayer");
if(!version)exit(0);

if (ereg(string:version, pattern:"^(9|10),0,0,.*"))
{
  if ( hotfix_missing(name:"892313") > 0  ) security_warning(port);
}

