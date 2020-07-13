#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18484);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(13950);
 script_cve_id("CAN-2005-1207");

 
 script_version("$Revision: 1.4 $");
 name["english"] = "Vulnerability in Web Client Service Could Allow Remote Code Execution (896426)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Windows contains a flaw in the Web Client service which may allow
an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need credentials to log into the remote host.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-028.mspx
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 896426";

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


if ( hotfix_check_sp(xp:2, win2003:2) <= 0 ) exit(0);

if ( hotfix_missing(name:"896426") > 0 )
	 security_hole(get_kb_item("SMB/transport"));


