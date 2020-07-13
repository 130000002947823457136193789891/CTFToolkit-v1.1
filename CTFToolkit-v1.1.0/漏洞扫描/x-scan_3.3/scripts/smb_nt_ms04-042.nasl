#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15965);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(11919, 11920);
 script_cve_id("CAN-2004-0899", "CAN-2004-0900");
 name["english"] = "Vulnerabilities in DHCP (885249) (registry check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has the Windows DHCP server installed.

There is a flaw in the remote version of this server which may allow an
attacker to execute arbitrary code on the remote host with SYSTEM
privileges.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-042.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS04-042";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");


if ( hotfix_check_nt_server() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_check_dhcpserver_installed() <= 0 ) exit(0);

if ( hotfix_missing(name:"885249") > 0 )
	security_hole(get_kb_item("SMB/transport"));
