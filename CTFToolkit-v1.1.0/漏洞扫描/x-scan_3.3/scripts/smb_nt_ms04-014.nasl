#
# (C) Tenable Network Security
#
if(description)
{
 script_id(12207);
 script_bugtraq_id(10112);
 script_cve_id("CAN-2004-0197");
 
 script_version("$Revision: 1.6 $");

 name["english"] = "Microsoft Hotfix KB837001 (registry check)";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host has a bug in its Microsoft Jet Database Engine (837001).

An attacker may exploit one of these flaws to execute arbitrary code on the
remote system.

To exploit this flaw, an attacker would need the ability to craft a specially
malformed database query and have this engine execute it.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-014.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-014";

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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB837001") > 0 )
	security_hole(get_kb_item("SMB/transport"));

