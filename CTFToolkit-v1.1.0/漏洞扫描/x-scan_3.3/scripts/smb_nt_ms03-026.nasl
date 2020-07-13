#
# (C) Tenable Network Security
#
#
#

if(description)
{
 script_id(11790);
 script_bugtraq_id(8205, 8458, 8460);
 script_version("$Revision: 1.20 $");
 script_cve_id("CAN-2003-0352", "CAN-2003-0715", "CAN-2003-0528", "CAN-2003-0605");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0011");
 
 name["english"] = "Buffer overrun in RPC Interface (824146)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Windows which has a flaw in 
its RPC interface, which may allow an attacker to execute arbitrary code 
and gain SYSTEM privileges.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-039.mspx
 
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q824146";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl", "msrpc_dcom2.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( get_kb_item("SMB/KB824146") ) exit(0);

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"824146") > 0 && 
     hotfix_missing(name:"828741") > 0 &&
     hotfix_missing(name:"873333") > 0  )
	security_hole(get_kb_item("SMB/transport"));
