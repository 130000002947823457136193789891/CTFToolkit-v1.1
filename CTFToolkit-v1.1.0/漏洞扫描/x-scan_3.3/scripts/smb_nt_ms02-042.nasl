#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11091);
 script_bugtraq_id(5480);
 script_version("$Revision: 1.17 $");
 script_cve_id("CVE-2002-0720");
 name["english"] = "Windows Network Manager Privilege Elevation (Q326886)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A flaw in the Windows 2000 Network Connection Manager
could enable privilege elevation.

Impact of vulnerability: Elevation of Privilege 

Affected Software: 

Microsoft Windows 2000 

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical

See
http://www.microsoft.com/technet/security/bulletin/ms02-042.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q326886, Network Elevated Privilege";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SECNAP Nework Security, LLC");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(win2k:4) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q326886") > 0 )
	security_hole(get_kb_item("SMB/transport"));

