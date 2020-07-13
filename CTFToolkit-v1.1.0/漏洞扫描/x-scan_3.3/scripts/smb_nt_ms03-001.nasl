#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11212);
 script_bugtraq_id(6666);
 script_cve_id("CAN-2003-0003");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0007");
 script_version("$Revision: 1.10 $");

 name["english"] = "Unchecked buffer in Locate Service";

 script_name(english:name["english"]);
 
 desc["english"] = "
The Microsoft Locate service is a name server that maps logical
names to network-specific names.

There is a security vulnerability in this server which allows
an attacker to execute arbitrary code in it by sending a specially
crafted packet to it.

Maximum Severity Rating: Critical 

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Microsoft Windows NT 4.0
Microsoft Windows NT 4.0, Terminal Server Edition
Microsoft Windows 2000
Microsoft Windows XP

See
http://www.microsoft.com/technet/security/bulletin/ms03-001.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix 810833";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl",
		     "smb_enum_services.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if  ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if  ( hotfix_missing(name:"Q810833") > 0 )
	{ 
	 svcs = get_kb_item("SMB/svcs");
 	 if(svcs && "[RpcLocator]" >!< svcs)exit(0); 
	 security_hole(get_kb_item("SMB/transport"));
	}
