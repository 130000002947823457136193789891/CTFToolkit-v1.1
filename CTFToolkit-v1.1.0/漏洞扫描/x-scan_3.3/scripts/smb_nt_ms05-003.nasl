#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16125);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(12228);
 script_cve_id("CAN-2004-897");
 name["english"] = "Indexing Service Code Execution (871250) (registry check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host contains a version of the Indexing Service which is
vulnerable to a security flaw which may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious query.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-003.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS05-003";

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

if ( hotfix_check_sp(xp:2, win2k:5, win2003:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"871250") > 0 )
	security_hole(get_kb_item("SMB/transport"));
