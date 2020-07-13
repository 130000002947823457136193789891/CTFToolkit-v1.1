#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18482);
 script_version("$Revision: 1.2 $");
 script_bugtraq_id(13953);
 script_cve_id("CAN-2005-1208");

 
 script_version("$Revision: 1.2 $");
 name["english"] = "Vulnerability in HTML Help Could Allow Remote Code Execution (896358)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host contains a version of the HTML Help ActiveX control which
is vulnerable to a security flaw which may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious web page
and entice a victim to visit this web page.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-026.mspx
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 896358";

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


if ( hotfix_check_sp(xp:3, win2003:2, win2k:5) <= 0 ) exit(0);

if ( hotfix_missing(name:"896358") > 0 )
	 security_hole(get_kb_item("SMB/transport"));


