#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18485);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(13948);
 script_cve_id("CAN-2005-1214");

 
 script_version("$Revision: 1.3 $");
 name["english"] = "Vulnerability in Microsoft Agent Could Allow Spoofing (890046)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Windows contains a flaw in the Microsoft Agent service 
which may allow an attacker to spoof the content of a web site.

To exploit this flaw, an attacker would need to set up a rogue web site and 
lure a victim on the remote host into visiting it.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-032.mspx
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 890046";

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

if ( hotfix_missing(name:"890046") > 0 )
	 security_warning(get_kb_item("SMB/transport"));


