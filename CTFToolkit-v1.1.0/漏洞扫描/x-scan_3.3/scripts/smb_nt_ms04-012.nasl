#
# (C) Tenable Network Security
#
if(description)
{
 script_id(12206);
 script_bugtraq_id(10121, 10123, 10127, 8811);
 script_cve_id( "CAN-2003-0813", "CAN-2004-0116", "CAN-2003-0807", "CAN-2004-0124");
 if( defined_func("script_xref") )script_xref(name:"IAVA", value:"2004-A-0005");

 
 script_version("$Revision: 1.8 $");

 name["english"] = "Microsoft Hotfix KB828741 (registry check)";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host has multiple bugs in its RPC/DCOM implementation (828741).

An attacker may exploit one of these flaws to execute arbitrary code on the
remote system.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-012.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-012";

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
if ( hotfix_missing(name:"KB828741") > 0 )
	security_hole(get_kb_item("SMB/transport"));

