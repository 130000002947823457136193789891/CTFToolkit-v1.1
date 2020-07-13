#
# (C) Tenable Network Security
#
if(description)
{
 script_id(18020);
 script_bugtraq_id(13132);
 script_cve_id("CAN-2005-0063");

 script_version("$Revision: 1.3 $");
 name["english"] = "Vulnerability in Windows Shell (893086)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Windows contains a flaw in the Windows Shell which
may allow an attacker to elevate his privileges and/or execute arbitrary
code on the remote host.

To exploit this flaw, an attacker would need to lure a victim into visiting
a malicious website or into opening a malicious file attachment.

Solution : http://www.microsoft.com/technet/security/bulletin/MS05-016.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 893086 has been installed";

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

if ( hotfix_check_sp(win2k:5, xp:3, win2003:1) <= 0 ) exit(0);


if ( hotfix_missing(name:"893086") > 0  )
	security_hole(get_kb_item("SMB/transport"));
