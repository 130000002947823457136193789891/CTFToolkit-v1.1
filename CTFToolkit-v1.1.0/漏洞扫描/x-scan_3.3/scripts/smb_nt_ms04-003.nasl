#
# (C) Tenable Network Security
#
if(description)
{
 script_id(11990);
 script_bugtraq_id(9407);
 script_version("$Revision: 1.14 $");
 script_cve_id("CAN-2003-0903");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-B-0001");

 name["english"] = "MDAC Buffer Overflow (832483)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Microsoft Data Access Component (MDAC) server is vulnerable to a 
flaw which could allow an attacker to execute arbitrary code on this host, 
provided he can simulate responses from a SQL server.

To exploit this flaw, an attacker would need to wait for a host running
a vulnerable MDAC implementation to send a broadcast query. He would then
need to send a malicious packet pretending to come from a SQL server.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-003.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of MDAC";

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

if ( hotfix_check_sp(xp:2, win2k:5, win2003:1) <= 0 ) exit(0);


if ( ( version =  hotfix_data_access_version()) == NULL ) exit(0);
if(ereg(pattern:"2\.6[3-9].*", string:version))exit(0); # SP3 applied

if ( hotfix_missing(name:"KB832483") > 0 &&
     hotfix_missing(name:"Q832483") > 0 )
	security_warning(get_kb_item("SMB/transport"));

