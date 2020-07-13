#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11144);
 script_version("$Revision: 1.6 $");
 script_cve_id("CAN-2002-0699");
 name["english"] = "Flaw in Certificate Enrollment Control (Q323172)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A vulnerability in the Certificate Enrollment
ActiveX Control in Microsoft Windows 98, Windows 98
Second Edition, Windows Millennium, Windows NT 4.0,
Windows 2000, and Windows XP allows remote attackers
to delete digital certificates on a user's system
via HTML.

Impact of vulnerability: Denial of service 

Maximum Severity Rating: Critical 

Recommendation: Customers should install the patch immediately 

Affected Software: 

Microsoft Windows 98 
Microsoft Windows 98 Second Edition 
Microsoft Windows Millennium 
Microsoft Windows NT 4.0 
Microsoft Windows 2000 
Microsoft Windows XP 

See
http://www.microsoft.com/technet/security/bulletin/ms02-048.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q323172, Certificate Enrollment Flaw";

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

if ( hotfix_check_sp(nt:7, win2k:4, xp:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q323172") > 0 )
	security_hole(get_kb_item("SMB/transport"));
