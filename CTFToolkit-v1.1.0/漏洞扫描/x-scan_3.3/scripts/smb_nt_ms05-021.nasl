#
# (C) Tenable Network Security
#
if(description)
{
 script_id(18024);
 script_version("$Revision: 1.3 $");
 script_cve_id("CAN-2005-0560");
 script_bugtraq_id(13118);
 name["english"] = "Vulnerability in SMTP Could Allow Remote Code Execution (894549)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host contains a flaw in its SMTP service which could allow remote
code execution.

Vulnerable services are  Exchange 2003 (Windows 2000) and Exchange 2000.

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-021.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix 894549";

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

if ( hotfix_check_nt_server() <= 0 ) exit(0);

version = get_kb_item ("SMB/Exchange/Version");
sp = get_kb_item ("SMB/Exchange/SP");


if ( ! version ) exit(0);

if ( version == 65 )
{
 if (sp && (sp >= 2)) exit (0);

 if ( hotfix_missing(name:"894549") > 0 )
   security_hole(get_kb_item("SMB/transport")); 

 exit (0);
}

if (version == 60)
{
 if (sp && (sp >= 4)) exit (0);

 if ( hotfix_missing(name:"894549") > 0 )
   security_hole(get_kb_item("SMB/transport")); 

 exit (0);
}
