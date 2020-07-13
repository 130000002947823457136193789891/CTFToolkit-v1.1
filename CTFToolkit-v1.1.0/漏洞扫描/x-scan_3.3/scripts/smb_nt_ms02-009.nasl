#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10926);
 script_bugtraq_id(4158);
 script_version("$Revision: 1.17 $");
 script_cve_id("CVE-2002-0052");
 name["english"] = "IE VBScript Handling patch (Q318089)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Incorrect VBScript Handling in IE can Allow Web 
Pages to Read Local Files.

Impact of vulnerability: Information Disclosure

Affected Software: 

Microsoft Internet Explorer 5.01
Microsoft Internet Explorer 5.5 
Microsoft Internet Explorer 6.0 

See
http://www.microsoft.com/technet/security/bulletin/ms02-009.mspx
and: Microsoft Article
Q319847 MS02-009 May Cause Incompatibility Problems Between
 VBScript and Third-Party Applications

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the IE VBScript Handling patch (Q318089) is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 script_exclude_keys("SMB/WinXP/ServicePack");
 exit(0);
}

include("smb_hotfixes.inc");

port = get_kb_item("SMB/transport");
if(!port) port = 139;

key = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{4f645220-306d-11d2-995d-00c04f98bbc9}/Version");
if (!key) exit (0);


if(ereg(pattern:"^([1-4],.*|5,([0-5],.*|6,0,([0-9]?[0-9]?[0-9]$|[0-6][0-9][0-9][0-9]|7([0-3]|4([01]|2[0-5])))))", string:key))
{ 
  security_hole(port);
  exit(0);
}
