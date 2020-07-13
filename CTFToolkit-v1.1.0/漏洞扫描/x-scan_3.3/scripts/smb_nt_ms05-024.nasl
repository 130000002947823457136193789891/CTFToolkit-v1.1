#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18215);
 script_version("$Revision: 1.2 $");
 script_bugtraq_id(13248);
 script_cve_id("CAN-2005-1191");

 
 script_version("$Revision: 1.2 $");
 name["english"] = "Vulnerability in Web View Could Allow Code Execution (894320)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Microsoft Windows which contains a 
security flaw in the Web View of the Windows Explorer which may allow an 
attacker to execute arbitrary code on the remote host.

To succeed, the attacker would have to send a rogue file to a user of the 
remote computer and have it preview it using the Web View with the Windows 
Explorer.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms05-024.mspx
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of KB894320";

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


if ( hotfix_check_sp(win2k:5) <= 0 ) exit(0);

if ( hotfix_missing(name:"894320") > 0 )
	security_hole(get_kb_item("SMB/transport"));
