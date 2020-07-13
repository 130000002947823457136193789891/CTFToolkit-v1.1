#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11194);
 script_bugtraq_id(6427);
 script_cve_id("CAN-2002-1327");
 script_version("$Revision: 1.6 $");

 name["english"] = "Unchecked Buffer in XP Shell Could Enable System Compromise (329390)";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible for a malicious user to mount a buffer
overrun attack using windows XP shell.

A successful attack could have the effect of either causing
the Windows Shell to fail, or causing an attacker's code to run on
the user's computer in the security context of the user.

Maximum Severity Rating: Critical 

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Microsoft Windows XP.

See
http://www.microsoft.com/technet/security/bulletin/ms02-072.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix 329390, Flaw in Microsoft XP Shell";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SECNAP Network Security, LLC");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q329390") > 0 )
	security_hole(get_kb_item("SMB/transport"));
