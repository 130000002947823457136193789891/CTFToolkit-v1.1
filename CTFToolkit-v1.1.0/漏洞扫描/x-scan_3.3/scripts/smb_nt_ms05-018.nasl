#
# (C) Tenable Network Security
#
if(description)
{
 script_id(18022);
 script_bugtraq_id(13121, 13115, 13110, 13109);
 script_cve_id("CAN-2005-0551", "CAN-2005-0550", "CAN-2005-0060");
 script_version("$Revision: 1.5 $");
 name["english"] = "Vulnerabilities in Windows Kernel (890859)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host contains a version of the Windows kernel which is vulnerable
to a security flaw which may allow a local user to elevate his privileges
or to crash the remote host (therefore causing a denial of service).

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-018.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for 890859";

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


if ( hotfix_check_sp(xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"890859") > 0 )
	security_hole(get_kb_item("SMB/transport"));
