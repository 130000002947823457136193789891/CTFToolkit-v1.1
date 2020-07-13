#
# (C) Tenable Network Security
#
if(description)
{
 script_id(11683);
 script_bugtraq_id(7731, 7733, 7734, 7735);
 script_cve_id("CAN-2003-0224", "CAN-2003-0225", "CAN-2003-0226");

 script_version("$Revision: 1.9 $");
 name["english"] = "Cumulative Patch for Internet Information Services (Q11114)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Cumulative Patch for Microsoft IIS (Q11114)

The remote host is running a version of IIS which is vulnerable to
various flaws which may allow remote attackers to disable this
service remotely and local attackers (or remote attackers with
the ability to upload arbitrary files on this server) to 
gain SYSTEM level access on this host.


Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical 

Affected Software: 

Microsoft Internet Information Server 4.0 
Microsoft Internet Information Services 5.0 
Microsoft Internet Information Services 5.1 

See
http://www.microsoft.com/technet/security/bulletin/ms03-018.mspx

Supersedes
http://www.microsoft.com/technet/security/bulletin/ms02-062.mspx
http://www.microsoft.com/technet/security/bulletin/ms02-028.mspx
http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if HF Q811114 has been installed";

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

if ( hotfix_check_iis_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q811114") > 0  )
	security_hole(get_kb_item("SMB/transport"));

