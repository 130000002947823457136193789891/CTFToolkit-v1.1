#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11147);
 script_bugtraq_id(4387, 5874);
 script_version("$Revision: 1.9 $");
 script_cve_id("CAN-2002-0693", "CAN-2002-0694"); 

 name["english"] = "Unchecked Buffer in Windows Help(Q323255)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
An unchecked buffer in Windows help could allow an attacker to
could gain control over user's system.

Maximum Severity Rating: Critical 

Recommendation: Customers should install the patch immediately. 

Affected Software: 

Microsoft Windows 98 
Microsoft Windows 98 Second Edition 
Microsoft Windows Millennium Edition 
Microsoft Windows NT 4.0 
Microsoft Windows NT 4.0, Terminal Server Edition 
Microsoft Windows 2000 
Microsoft Windows XP 

See
http://www.microsoft.com/technet/security/bulletin/ms02-055.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q323255, Unchecked Buffer in Windows Help facility";

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
if ( hotfix_missing(name:"Q323255") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
