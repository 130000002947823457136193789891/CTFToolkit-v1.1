#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16299);
 script_version("$Revision: 1.1 $");
 script_bugtraq_id(8532);
 script_cve_id("CAN-2003-0661");
 name["english"] = "NetBIOS Name Service Reply Information Leakage (824105) (registry check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the NetBT name
service which suffers from a memory disclosure problem.

An attacker may send a special packet to the remote NetBT name
service, and the reply will contain random arbitrary data from 
the remote host memory. This arbitrary data may be a fragment from
the web page the remote user is viewing, or something more serious
like a POP password or anything else.

An attacker may use this flaw to continuously 'poll' the content
of the memory of the remote host and might be able to obtain sensitive
information.


Solution : See http://www.microsoft.com/technet/security/bulletin/ms03-034.mspx
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS03-034";

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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"824105") > 0 )
	security_hole(get_kb_item("SMB/transport"));
