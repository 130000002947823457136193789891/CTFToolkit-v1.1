#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11029);
 script_bugtraq_id(4852);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0366");
 name["english"] = "Windows RAS overflow (Q318138)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
An overflow in the RAS phonebook service allows a local user
to execute code on the system with the privileges of LocalSystem.

Impact of vulnerability: Elevation of Privilege 

Affected Software: 

Microsoft Windows NT 4.0 
Microsoft Windows NT 4.0 Server, Terminal Server Edition 
Microsoft Windows 2000 
Microsoft Windows XP

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical (locally)

See
http://www.microsoft.com/technet/security/bulletin/ms02-029.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q318138, Elevated Privilege";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");


if ( hotfix_check_sp(nt:7, win2k:3, xp:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q318138") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));

