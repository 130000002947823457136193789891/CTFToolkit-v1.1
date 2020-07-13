#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(10964);
 script_bugtraq_id(4287);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0367");
 name["english"] = "Windows Debugger flaw can Lead to Elevated Privileges (Q320206)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Authentication Flaw in Windows Debugger can Lead to Elevated 
Privileges (Q320206)

Impact of vulnerability: Elevation of Privilege 

Affected Software: 

Microsoft Windows NT 4.0 
Microsoft Windows NT 4.0 Server, Terminal Server Edition 
Microsoft Windows 2000 

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical (locally)

See
http://www.microsoft.com/technet/security/bulletin/ms02-024.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q320206, Elevated Privilege";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, win2k:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q320206") > 0 )
	security_hole(get_kb_item("SMB/transport"));

