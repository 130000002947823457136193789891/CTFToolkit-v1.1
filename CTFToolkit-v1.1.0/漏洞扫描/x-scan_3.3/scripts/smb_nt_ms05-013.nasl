#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16329);
 script_version("$Revision: 1.2 $");
 script_cve_id("CAN-2004-1319", "CAN-2005-0044");
 name["english"] = "Vulnerability in the DHTML Editing Component may allow code execution (891781)";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running a version of Windows which contains a flaw in
the DHTML Editing Component ActiveX Control.

An attacker may exploit this flaw to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to construct a malicious web page
and lure a victim into visiting it.


Solution : http://www.microsoft.com/technet/security/bulletin/ms05-013.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for KB 891781 via the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"891781") > 0  )
	security_hole(get_kb_item("SMB/transport"));
