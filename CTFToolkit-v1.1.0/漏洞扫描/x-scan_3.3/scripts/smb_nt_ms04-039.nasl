#
# This script was written by Noam Rathaus <noamr@beyondsecurity.com>
#
# See the Nessus Scripts License for details
#
# 
#
if(description)
{
 script_id(15714);
 script_version("$Revision: 1.3 $");
 script_cve_id("CAN-2004-0892");
 
 name["english"] = "ISA Server 2000 and Proxy Server 2.0 Internet Content Spoofing (888258)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The ISA Server 2000 and Proxy Server 2.0 have been found to be vulnerable to
a spoofing vulnerability that could enable an attacker to spoof trusted Internet 
content. Users could believe they are accessing trusted Internet content when 
in reality they are accessing malicious Internet content, for example a 
malicious Web site. However, an attacker would first have to persuade a user to 
visit the attacker's to attempt to exploit this vulnerability.

See http://www.microsoft.com/technet/security/bulletin/ms04-039.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q888258";

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

fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/408");
if(!fix)security_hole(port);
