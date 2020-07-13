#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11286);
 script_bugtraq_id(5478);
 script_cve_id("CAN-2002-0974");
 
 script_version("$Revision: 1.5 $");

 name["english"] = "Flaw in WinXP Help center could enable file deletion";

 script_name(english:name["english"]);
 
 desc["english"] = "
There is a security vulnerability in the remote Windows XP Help and Support
Center which can be exploited by an attacker to delete arbitrary file
on this host.

To do so, an attacker needs to create malicious web pages that must
be visited by the owner of the remote system.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms02-060.mspx
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q328940";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");


if ( hotfix_check_sp(xp:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q328940") > 0 )
	security_warning(get_kb_item("SMB/transport"));

