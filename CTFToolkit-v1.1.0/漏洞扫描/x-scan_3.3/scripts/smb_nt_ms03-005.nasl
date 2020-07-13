#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11231);
 script_bugtraq_id(6778);
 script_cve_id("CAN-2003-0004");
 script_version("$Revision: 1.9 $");

 name["english"] = "Unchecked Buffer in XP Redirector (Q810577)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is vulnerable to a flaw in the RPC redirector
which can allow a local attacker to run code of its choice
with the SYSTEM privileges.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-005.mspx
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q810577";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 SECNAP Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"810577") > 0 &&
     hotfix_missing(name:"885835") > 0  )
	security_warning(get_kb_item("SMB/transport"));
