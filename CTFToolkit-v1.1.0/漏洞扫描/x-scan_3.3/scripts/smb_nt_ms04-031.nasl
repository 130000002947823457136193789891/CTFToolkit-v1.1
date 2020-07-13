#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15456);
 script_bugtraq_id(11372);
 script_cve_id("CAN-2004-0206");

 script_version("$Revision: 1.5 $");
 name["english"] = "Vulnerability in NetDDE Could Allow Code Execution (841533)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Windows is affected by a vulnerability in 
Network Dynamic Data Exchange (NetDDE).

To exploit this flaw, NetDDE would have to be running and an attacker
with a specific knowledge of the vulnerability would need to send a malformed
NetDDE message to the remote host to overrun a given buffer.

Solution : http://www.microsoft.com/technet/security/bulletin/MS04-031.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 841533 has been installed";

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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"841533") > 0  )
	security_hole(get_kb_item("SMB/transport"));

