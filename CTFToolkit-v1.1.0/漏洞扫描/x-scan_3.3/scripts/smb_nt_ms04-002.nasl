#
# (C) Tenable Network Security
#
if(description)
{
 script_id(11989);
 script_bugtraq_id(9118, 9409);
 script_version("$Revision: 1.9 $");
 script_cve_id("CAN-2003-0904");
 name["english"] = "Exchange Privilege Escalation (832759)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running an unpatched version of Microsoft Exchange which
may allow an attacker with a valid Exchange account to access another user's
mailbox using Outlook for Web Access

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-002.mspx
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q832759";

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

if ( hotfix_check_nt_server() <= 0 ) exit(0);

version = get_kb_item ("SMB/Exchange/Version");
if (!version || (version != 65)) exit(0);

sp = get_kb_item ("SMB/Exchange/SP");
if ( sp && (sp >= 1)) exit (0);

if ( hotfix_missing(name:"Q832759") > 0 )
	security_warning(get_kb_item("SMB/transport"));
