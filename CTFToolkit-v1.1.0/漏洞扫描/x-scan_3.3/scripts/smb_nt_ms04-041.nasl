#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15966);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(11927, 11929);
 script_cve_id("CAN-2004-0571", "CAN-2004-0901");
 name["english"] = "Vulnerabilities in WordPad (885836)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host contains a version of Microsoft WordPad which is vulnerable
to two security flaws.

To exploit these flaws an attacker would need to send a malformed Word file
to a victim on the remote host and wait for him to open the file using WordPad.

Opening the file with WordPad will trigger a buffer overflow which may allow
an attacker to execute arbitrary code on the remote host with the privileges
of the user.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-041.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS04-041";

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


if ( hotfix_missing(name:"885836") > 0 )
	security_hole(get_kb_item("SMB/transport"));
