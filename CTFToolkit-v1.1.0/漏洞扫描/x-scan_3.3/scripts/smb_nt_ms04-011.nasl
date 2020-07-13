#
# (C) Tenable Network Security
#
if(description)
{
 script_id(12205);
 script_bugtraq_id(10111, 10113, 10117, 10119, 10122, 10124, 10125);
 script_cve_id( "CAN-2003-0907", "CAN-2003-0908", "CAN-2003-0909",
		"CAN-2003-0910", "CAN-2004-0117", "CAN-2004-0118", "CAN-2004-0119", "CAN-2004-0121");
 if(defined_func("script_xref"))script_xref(name:"CVE", value:"CAN-2003-0533");
 if(defined_func("script_xref"))script_xref(name:"CVE", value:"CAN-2003-0663");
 if(defined_func("script_xref"))script_xref(name:"CVE", value:"CAN-2003-0719");
 if(defined_func("script_xref"))script_xref(name:"CVE", value:"CAN-2003-0806");
 if(defined_func("script_xref"))script_xref(name:"CVE", value:"CAN-2003-0906");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0006");

 script_version("$Revision: 1.12 $");

 name["english"] = "Microsoft Hotfix KB835732 (registry check)";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is missing a critical Microsoft Windows Security Update (835732).

This update fixes various flaws which may allow an attacker to execute arbitrary code
on the remote host.

Solution : Install the Windows cumulative update from Microsoft 
See also : http://www.microsoft.com/technet/security/bulletin/ms04-011.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-011";

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
if ( hotfix_missing(name:"KB835732") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
 
