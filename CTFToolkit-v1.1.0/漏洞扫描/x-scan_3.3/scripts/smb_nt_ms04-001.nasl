#
# This script was written by Jeff Adams <jadams@netcentrics.com> 
#
# See the Nessus Scripts License for details
#
# 
#
if(description)
{
 script_id(11992);
 script_bugtraq_id(9408);
 script_version("$Revision: 1.6 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-B-0002");
 script_cve_id("CAN-2003-0819");
 
 name["english"] = "Vulnerability in Microsoft ISA Server 2000 H.323 Filter(816458)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A security vulnerability exists in the H.323 filter for Microsoft Internet 
Security and Acceleration Server 2000 that could allow an attacker
to overflow a buffer in the Microsoft Firewall Service in Microsoft Internet 
Security and Acceleration Server 2000.

An attacker who successfully exploited this vulnerability could try to run 
code of their choice in the security context of the Microsoft Firewall Service. 
This would give the attacker complete control over the system. 
The H.323 filter is enabled by default on servers running ISA Server 2000 
computers that are installed in integrated or firewall mode.

Impact of vulnerability: Remote code execution  

Affected Software: 

Microsoft Internet Security and Acceleration Server 2000 Gold, SP1

Solution: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical 

See http://www.microsoft.com/technet/security/bulletin/ms04-001.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q816458";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Jeff Adams");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);

fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/291");
if(!fix)security_hole(port);
