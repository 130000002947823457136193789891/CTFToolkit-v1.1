#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(10943);
 script_bugtraq_id(4006, 4474, 4476, 4478, 4490, 6069, 6070, 6071, 6072);
 script_cve_id("CVE-2002-0147", "CVE-2002-0149",
 	       "CVE-2002-0150", "CAN-2002-0224",
 	       "CAN-2002-0869", "CAN-2002-1182",
	       "CAN-2002-1180", "CAN-2002-1181");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0002");
 script_version("$Revision: 1.21 $");
 name["english"] = "Cumulative Patch for Internet Information Services (Q327696)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Cumulative Patch for Microsoft IIS (Q327696)

Impact of vulnerability: Ten new vulnerabilities, the most
serious of which could enable code of an attacker's choice
to be run on a server.

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical 

Affected Software: 

Microsoft Internet Information Server 4.0 
Microsoft Internet Information Services 5.0 
Microsoft Internet Information Services 5.1 

See
http://www.microsoft.com/technet/security/bulletin/ms02-062.mspx

Supersedes

http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether October 30, 2002 IIS Cumulative patches (Q327696) are installed";

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

if ( hotfix_check_iis_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:3, xp:1 ) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q811114") > 0 &&
     hotfix_missing(name:"Q327696") > 0  ) 
	security_hole(get_kb_item("SMB/transport"));
     

