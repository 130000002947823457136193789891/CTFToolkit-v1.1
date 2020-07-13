#
# (C) Tenable Network Security
#
#
#

if(description)
{
 script_id(11789);
 script_bugtraq_id(8154, 8205);
 script_version("$Revision: 1.9 $");
 script_cve_id("CAN-2003-0350");
 
 name["english"] = "Flaw in message handling through utility mgr";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host runs a version of windows which has a flaw in the way
the utility manager handles Windows messages. As a result, it is possible
for a local user to gain additional privileges on this host.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-025.mspx
 
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q822679";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(win2k:4) <= 0 ) exit(0);
if ( hotfix_missing(name:"822679") > 0 && hotfix_missing(name:"842526") > 0 )
	security_hole(get_kb_item("SMB/transport"));
