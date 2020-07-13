#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15455);
 script_bugtraq_id(11384);
 script_cve_id("CAN-2003-0718");

 script_version("$Revision: 1.4 $");
 name["english"] = "WebDAV XML Message Handler Denial of Service (824151)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Windows and IIS which is vulnerable
to a remote denial of service attack through the WebDAV XML Message Handler.

An attacker may exploit this flaw to prevent the remote web server from
working properly.

Solution : http://www.microsoft.com/technet/security/bulletin/MS04-030.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 824151 has been installed";

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

if ( hotfix_check_iis_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:0, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"824151") > 0  )
	security_hole(get_kb_item("SMB/transport"));

