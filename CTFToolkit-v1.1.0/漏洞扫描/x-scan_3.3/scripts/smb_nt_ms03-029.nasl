#
# (C) Tenable Network Security
#
#
#

if(description)
{
 script_id(11802);
 script_bugtraq_id(8259);
 script_version("$Revision: 1.5 $");
 script_cve_id("CAN-2003-0525");
 
 name["english"] = "Flaw in Windows Function may allow DoS (823803)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Windows NT 4.0 which has a flaw in 
one of its function which may allow a user to cause a denial
of service on this host.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-029.mspx
 
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix 823803";

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

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q823803") > 0 ) 
	security_warning(get_kb_item("SMB/transport"));
