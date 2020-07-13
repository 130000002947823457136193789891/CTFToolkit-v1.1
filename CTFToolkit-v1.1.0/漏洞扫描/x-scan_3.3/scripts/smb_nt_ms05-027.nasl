#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18483);
 script_version("$Revision: 1.2 $");
 script_bugtraq_id(13942);
 script_cve_id("CAN-2005-1208");

 
 script_version("$Revision: 1.2 $");
 name["english"] = "Vulnerability in SMB Could Allow Remote Code Execution (896422)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Windows contains a flaw in the Server Message
Block (SMB) implementation which may allow an attacker to execute arbitrary 
code on the remote host.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-027.mspx
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 896422";

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

if ( hotfix_missing(name:"896422") > 0 )
	 security_hole(get_kb_item("SMB/transport"));


