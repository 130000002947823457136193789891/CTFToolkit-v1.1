#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16327);
 script_version("$Revision: 1.2 $");
 script_cve_id("CAN-2005-0047", "CAN-2005-0044");
 script_bugtraq_id(12488, 12483);
 name["english"] = "Vulnerability in OLE and COM Could Allow Code Execution (873333)";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running a version of Windows which is vulnerable to two
vulnerabilities when dealing with OLE and/or COM. 

These vulnerabilities may allow a local user to escalate his privileges
and allow a remote user to execute arbitrary code on the remote host.

To exploit these flaws, an attacker would need to send a specially crafted
document to a victim on the remote host.


Solution : http://www.microsoft.com/technet/security/bulletin/ms05-012.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for KB 873333 via the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"873333") > 0  )
	security_hole(get_kb_item("SMB/transport"));
