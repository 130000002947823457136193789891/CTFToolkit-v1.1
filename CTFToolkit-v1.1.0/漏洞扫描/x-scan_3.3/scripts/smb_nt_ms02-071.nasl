#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11191);
 script_bugtraq_id(5927);
 script_version("$Revision: 1.13 $");
 script_cve_id("CAN-2002-1230");
 name["english"] = "WM_TIMER Message Handler Privilege Elevation (Q328310)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A security issue has been identified in WM_TIMER that
could allow an attacker to compromise a computer running 
Microsoft Windows and gain complete control over it.

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical 

Affected Software: 

Microsoft Windows NT 4.0 
Microsoft Windows NT 4.0, Terminal Server Edition 
Microsoft Windows 2000 
Microsoft Windows XP 

See
http://www.microsoft.com/technet/security/bulletin/ms02-071.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks Registry for WM_TIMER Privilege Elevation Hotfix (Q328310)";

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

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7) > 0 )
{
 if (hotfix_missing(name:"840987") == 0 ) exit(0);
}
if ( hotfix_check_sp(win2k:4) > 0 )
{
 if (hotfix_missing(name:"840987") == 0 ) exit(0);
 if (hotfix_missing(name:"841533") == 0 ) exit(0);
}


if ( hotfix_missing(name:"328310") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
