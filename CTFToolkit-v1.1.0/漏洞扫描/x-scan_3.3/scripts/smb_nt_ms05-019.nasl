#
# (C) Tenable Network Security
#
if(description)
{
 script_id(18023);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(13124, 13116);
 script_cve_id("CAN-2005-0048", "CAN-2004-0790", "CAN-2004-1060", "CAN-2004-0230", "CAN-2005-0688");

 name["english"] = "Vulnerabilities in TCP/IP Could Allow Remote Code Execution (893066)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host runs a version of Windows which has a flaw in its TCP/IP
stack.

The flaw may allow an attacker to execute arbitrary code with SYSTEM
privileges on the remote host, or to perform a denial of service attack
against the remote host.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-019.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for 893066";

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

if ( hotfix_missing(name:"893066") > 0 )
	security_hole(get_kb_item("SMB/transport"));
