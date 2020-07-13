#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16331);
 script_bugtraq_id(12486);
 script_cve_id("CAN-2005-0051");
 script_version("$Revision: 1.2 $");


 name["english"] = "Vulnerability in Windows Could Allow Information Disclosure (888302)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Windows contains a flaw which may allow an attacker
to cause it to disclose information over the use of a named pipe through
a NULL session.

An attacker may exploit this flaw to gain more knowledge about the
remote host.

Solution : http://www.microsoft.com/technet/security/bulletin/MS05-007.mspx
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 888302 has been installed";

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

if ( hotfix_check_sp(xp:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"888302") > 0  )
	security_warning(get_kb_item("SMB/transport"));
