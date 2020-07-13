#
# written by Renaud Deraison <deraison@cvs.nessus.org>
#


if(description)
{
 script_id(11485);
 script_bugtraq_id(6005);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CAN-2002-1561");
 
 name["english"] = "Flaw in RPC Endpoint Mapper (MS03-010)";

 script_name(english:name["english"]);
 
 desc["english"] = "
A flaw exists in the RPC endpoint mapper, which can be used by an attacker
to disable it remotely.

An attacker may use this flaw to prevent this host from working
properly


Affected Software:

Microsoft Windows NT 4
Microsoft Windows 2000
Microsoft Windows XP

Solution for Win2k and XP: see
http://www.microsoft.com/technet/security/bulletin/ms03-010.mspx

There is no patch for NT4.

Microsoft strongly recommends that customers still using
Windows NT 4.0 protect those systems by placing them behind a
firewall which is filtering traffic on Port 135.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for SP version";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"331953") > 0 && 
     hotfix_missing(name:"824146") > 0 && 
     hotfix_missing(name:"873333") > 0 && 
     hotfix_missing(name:"828741") > 0 )
  security_hole(get_kb_item("SMB/transport"));
