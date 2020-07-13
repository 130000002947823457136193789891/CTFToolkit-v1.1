#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(11300);
 script_bugtraq_id(5556);
 script_version("$Revision: 1.8 $");
 script_cve_id("CAN-2002-0724");
 
 name["english"] = "Unchecked buffer in Network Share Provider (Q326830)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is vulnerable to a denial of service attack,
which could allow an attacker to crash it by sending a specially
crafted SMB (Server Message Block) request to it.

Impact of vulnerability: Denial of Service / Elevation of Privilege 

Maximum Severity Rating: Moderate

Solution :  http://www.microsoft.com/technet/security/bulletin/ms02-045.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q326830";

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

if ( hotfix_check_sp(nt:7, win2k:4, xp:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q326830") > 0 )  
	security_hole(get_kb_item("SMB/transport"));

