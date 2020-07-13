#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11541);
 script_bugtraq_id(7370);
 script_cve_id("CAN-2003-0112");
 script_version ("$Revision: 1.14 $");

 name["english"] = "Buffer overrun in NT kernel message handling";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Windows has a flaw in the way the kernel passes error
messages to a debugger. An attacker could exploit it to gain elevated privileges
on this host.

To successfully exploit this vulnerability, an attacker would need a local
account on this host.

Solution : see http://www.microsoft.com/technet/security/bulletin/MS03-013.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks hotfix Q811493";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"811493") > 0 && 
     hotfix_missing(name:"840987") > 0 && 
     hotfix_missing(name:"885835") > 0 )
	{
	if ( hotfix_check_sp(xp:2) > 0  &&
	     hotfix_missing(name:"890859") == 0 ) exit(0);

	security_hole(get_kb_item("SMB/transport"));
	}

