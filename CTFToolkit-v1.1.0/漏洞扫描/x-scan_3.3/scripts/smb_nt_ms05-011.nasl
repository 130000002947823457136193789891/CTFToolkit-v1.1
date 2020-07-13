#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16326);
 script_version("$Revision: 1.3 $");
 script_cve_id("CAN-2005-0045");
 script_bugtraq_id(12484);

 script_version("$Revision: 1.3 $");
 name["english"] = "Vulnerability in SMB may allow remote code execution (885250)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Windows contains a flaw in the Server Message
Block (SMB) implementation which may allow an attacker to execute arbitrary 
code on the remote host.

To exploit this flaw, an attacker would need to send malformed responses
to the remote SMB client, and would be able to either execute arbitrary
code on the remote host or to perform a denial of service.

Solution : http://www.microsoft.com/technet/security/bulletin/MS05-011.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 885250 has been installed";

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

if ( hotfix_check_sp(nt:7, win2k:5, xp:3, win2003:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"885250") > 0  )
	security_hole(get_kb_item("SMB/transport"));
