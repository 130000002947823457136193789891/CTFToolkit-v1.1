#
# (C) Tenable Network Security
#
#
#

if(description)
{
 script_id(13642);
 script_bugtraq_id(9510);
 script_version("$Revision: 1.6 $");
 script_cve_id("CAN-2004-0420");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2004-B-0010");

 
 name["english"] = "Buffer overrun in Windows Shell (839645)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Windows which has a flaw in 
its shell. An attacker could persuade a user on the remote host to execute
a rogue program by using a CLSID instead of a file type, thus fooling
the user into thinking that he will not execute an application but simply
open a document.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-024.mspx
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-024 over the registry";

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
if ( hotfix_missing(name:"839645") > 0 &&
     hotfix_missing(name:"841356") > 0  )
	security_warning(get_kb_item("SMB/transport"));

