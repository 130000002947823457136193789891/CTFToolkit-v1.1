#
# (C) Tenable Network Security
#
if(description)
{
 script_id(12052);
 script_bugtraq_id(9633, 9635, 13300);
 script_version("$Revision: 1.14 $");
 script_cve_id("CAN-2003-0818");
 name["english"] = "ASN.1 parsing vulnerability (828028)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Windows host has a ASN.1 library which is vulnerable to a 
flaw which could allow an attacker to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to send a specially crafted
ASN.1 encoded packet (either an IPsec session negotiation, or an HTTPS request)
with improperly advertised lengths.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-007.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of MDAC";

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
if ( hotfix_missing(name:"835732") > 0 &&
     hotfix_missing(name:"828028") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));

