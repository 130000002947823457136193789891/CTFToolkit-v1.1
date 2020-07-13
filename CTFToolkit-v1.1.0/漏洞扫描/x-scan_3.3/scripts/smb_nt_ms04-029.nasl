#
# (C) Noam Rathaus
#
if(description)
{
 script_id(15467);
 script_bugtraq_id(11380);
 script_cve_id("CAN-2004-0569");
 script_version("$Revision: 1.2 $");

 name["english"] = "Vulnerability in RPC Runtime Library Could Allow Information Disclosure and Denial of Service (873350)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
An information disclosure and denial of service vulnerability exists when 
the RPC Runtime Library processes specially crafted messages.

An attacker who successfully exploited this vulnerability could potentially
read portions of active memory or cause the affected system to stop responding.

Solution : http://www.microsoft.com/technet/security/bulletin/MS04-029.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 873350 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"873350") > 0  )
	security_hole(get_kb_item("SMB/transport"));

