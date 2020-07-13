#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(10944);
 script_bugtraq_id(4426);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0151");
 name["english"] = "MUP overlong request kernel overflow Patch (Q311967)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Buffer overflow in Multiple UNC Provider (MUP) in Microsoft
Windows operating systems allows local users to cause a
denial of service or possibly gain SYSTEM privileges via a
long UNC request. 

Affected Software: 

Microsoft Windows NT 4.0 Workstation 
Microsoft Windows NT 4.0 Server 
Microsoft Windows NT 4.0 Server, Enterprise Edition 
Microsoft Windows NT 4 Terminal Server Edition 
Microsoft Windows 2000 Professional 
Microsoft Windows 2000 Server 
Microsoft Windows 2000 Advanced Server 
Microsoft Windows XP Professional 

See
http://www.microsoft.com/technet/security/bulletin/ms02-017.mspx

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "checks for Multiple UNC Provider Patch (Q311967)";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, win2k:3, xp:1) <= 0 ) exit(0); 
if ( hotfix_missing(name:"Q312895") > 0  ) 
	security_warning(get_kb_item("SMB/transport"));

