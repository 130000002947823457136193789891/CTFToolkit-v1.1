#
# This script was written by Renaud Deraison 
#
# See the Nessus Scripts License for details
#
#
#
#

if(description)
{
 script_id(11787);
 script_bugtraq_id(8152);
 script_version("$Revision: 1.19 $");
 script_cve_id("CAN-2003-0345");
 
 name["english"] = "SMB Request Handler Buffer Overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is vulnerable to a flaw in its SMB stack which may allow
an authenticated attacker to corrupt the memory of this host. This
may result in execution of arbitrary code on this host, or an attacker
may disable this host remotely.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-024.mspx
 

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q817606";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(xp:2, win2k:5) > 0 && hotfix_missing(name:"896422") == 0 ) exit(0);

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q817606") > 0 )
	security_hole(get_kb_item("SMB/transport"));

