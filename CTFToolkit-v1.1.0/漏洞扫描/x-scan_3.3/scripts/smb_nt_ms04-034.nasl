#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15459);
 script_bugtraq_id(11382);
 script_cve_id("CAN-2004-0575");

 script_version("$Revision: 1.3 $");
 name["english"] = "Vulnerability in zipped folders may allow code execution (873376)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Windows is vulnerable to a bug in the way it handles compressed
(zipped) folders, which may in turn be exploited by an attacker to execute arbitrary
code on the remote host.

To exploit this flaw, an attacker would need to send a specially crafted .zip
file to a victim on the remote host and wait for him to browse the file using
the Windows Explorer.

Solution : http://www.microsoft.com/technet/security/bulletin/MS04-034.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 873376 has been installed";

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
if ( hotfix_missing(name:"873376") > 0  )
	security_hole(get_kb_item("SMB/transport"));

