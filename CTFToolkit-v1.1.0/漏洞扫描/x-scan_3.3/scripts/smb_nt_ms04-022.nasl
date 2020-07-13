#
# (C) Tenable Network Security
#
if(description)
{
 script_id(13640);
 script_bugtraq_id(10708);
 script_version("$Revision: 1.7 $");
 script_cve_id("CAN-2004-0212");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0013");
 name["english"] = "Task Scheduler Vulnerability (841873)";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running a version of Windows which contains a flaw in
the task scheduler which may lead to arbitrary execution of commands 
on the remote host.

To exploit this vulnerability, an attacker would need to lure a user on
the remote host to take certain steps to execute a .job file, or to visit
a rogue web site, then he may be able to execute arbitrary commands on the 
remote host.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-022.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-022 over the registry";

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


if ( hotfix_check_sp(win2k:5, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB841873") > 0 )
	security_hole( get_kb_item("SMB/transport") );

