#
# (C) Tenable Network Security
#
if(description)
{
 script_id(13638);
 script_bugtraq_id(10710);
 script_version("$Revision: 1.4 $");
 script_cve_id("CAN-2004-0210");
 name["english"] = "Vulnerability in POSIX could allow code execution (841872)";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running a version of the posix subsystem which contains
a flaw which may allow a local attacker to execute arbitrary code on the host,
thus escalating his privileges and obtaining the full control of the remote
system.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-020.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-020 over the registry";

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

if ( hotfix_check_sp(nt:7, win2k:5) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB841872") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
