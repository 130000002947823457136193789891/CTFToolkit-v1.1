#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15963);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(11913, 11914);
 script_cve_id("CAN-2004-0893", "CAN-2004-0894");
 name["english"] = "Vulnerabilities in Windows Kernel and LSASS (885835)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running version of the NT kernel and LSASS which may
allow a local user to gain elevated privileged.

An attacker who has the ability to execute arbitrary commands on the remote
host may exploit these flaws to gain SYSTEM privileges.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-044.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS04-044";

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
if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"885835") > 0 )
	security_hole(get_kb_item("SMB/transport"));
