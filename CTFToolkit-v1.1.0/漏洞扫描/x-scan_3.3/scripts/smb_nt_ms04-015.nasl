#
# (C) Tenable Network Security
#
if(description)
{
 script_id(12235);
 script_bugtraq_id(10321);
 script_cve_id("CAN-2004-0199");
 script_version("$Revision: 1.5 $");
 name["english"] = "Microsoft Help Center Remote Code Execution (840374)";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host contains bugs in the Microsoft Help and Support Center 
in the way it handles HCP URL validation. (840374)

An attacker could use this bug to execute arbitrary commands on the
remote host. To exploit this bug, an attacker would need to lure a user
of the remote host into visiting a rogue website or to click on a link
received in an email.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-015.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-015 over the registry";

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
if ( hotfix_check_sp(xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB840374") > 0 )
	security_hole(get_kb_item("SMB/transport"));

