#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16124);
 script_version("$Revision: 1.5 $");
 script_bugtraq_id(12233);
 script_cve_id("CAN-2004-1305", "CAN-2004-1049");
 name["english"] = "Cursor and Icon Format Handling Code Execution (891711) (registry check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host contains a version of the Windows kernel which is vulnerable
to a security flaw in the way that cursors and icons are handleld. An attacker
may be able to execute arbitrary code on the remote host by constructing a
malicious web page and entice a victim to visit this web page. An attacker may
send a malicious email to the victim to exploit this flaw too.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-002.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS05-002";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");


if ( hotfix_check_sp(nt:7, xp:2, win2k:5, win2003:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"891711") > 0 )
	{
	# Superseeded by MS05-18
	if ( hotfix_check_sp(win2k:5, win2003:1, xp:2) > 0 && hotfix_missing(name:"890859") <= 0 ) exit(0);

	security_hole(get_kb_item("SMB/transport"));
	}
