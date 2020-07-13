#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15457);
 script_bugtraq_id(11365, 11369, 11375, 11378);
 script_cve_id("CAN-2004-0207", "CAN-2004-0208", "CAN-2004-0209", "CAN-2004-0211");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2004-A-0017");

 script_version("$Revision: 1.9 $");
 name["english"] = "Security Update for Microsoft Windows (840987)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing a security update for Microsoft Windows (840987).
The missing security update fixes issues in the following areas :

- Window Management
- Virtual DOS Machine
- Graphics Rendering Engine
- Windows Kernel


A local attacker may exploit any of these vulnerabilities to cause a local
denial of service or obtain higher privileges on the remote host.

Solution : http://www.microsoft.com/technet/security/bulletin/MS04-032.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 840987 has been installed";

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
if ( hotfix_missing(name:"840987") > 0  )
	{
   	# Superseed by MS05-018
	if ( hotfix_check_sp(win2003:1) > 0 &&
	     hotfix_missing(name:"890859") < 0 ) exit(0);

	security_hole(get_kb_item("SMB/transport"));
}

