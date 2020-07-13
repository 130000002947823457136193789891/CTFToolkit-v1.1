#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
# re-release, microsoft patched the patch, new qnumber, registry, etc

if(description)
{
 script_id(11178);
 script_bugtraq_id(5807, 6067);
 script_version("$Revision: 1.12 $");
 script_cve_id("CAN-2002-1214");

 name["english"] = "Unchecked Buffer in PPTP Implementation Could Enable DOS Attacks (Q329834)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Hotfix to fix Unchecked Buffer in PPTP Implementation 
 (Q329834) is not installed.

A security vulnerability results in the Windows 2000 and 
Windows XP implementations because of an unchecked buffer
in a section of code that processes the control data used
to establish, maintain and tear down PPTP connections. By
delivering specially malformed PPTP control data to an
affected server, an attacker could corrupt kernel memory
and cause the system to fail, disrupting any work in progress
on the system. 

Impact of vulnerability: Denial of service
Maximum Severity Rating: Critical 

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Microsoft Windows 2000 
Microsoft Windows XP 

See
http://www.microsoft.com/technet/security/bulletin/ms02-063.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q329834, Unchecked Buffer in PPTP DOS";

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

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q329834") > 0 )
	security_hole(get_kb_item("SMB/transport"));

