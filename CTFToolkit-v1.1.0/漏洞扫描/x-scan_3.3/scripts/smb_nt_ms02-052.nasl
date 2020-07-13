#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11177);
 script_bugtraq_id(6371, 6372);
 script_version("$Revision: 1.14 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-B-0002");
 script_cve_id("CAN-2002-1257","CAN-2002-1258","CAN-2002-1183","CAN-2002-0862");

 name["english"] = "Flaw in Microsoft VM Could Allow Code Execution (810030)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Hotfix to fix Flaw in Microsoft VM
could Allow Code Execution (810030)

Impact of vulnerability: Three vulnerabilities, the most
serious of which could enable an attacker to gain complete
control over a user's system. 

Maximum Severity Rating: Critical 

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Versions of the Microsoft virtual machine (Microsoft VM) are
identified by build numbers, which can be determined using the
JVIEW tool as discussed in the FAQ. All builds of the Microsoft
VM up to and including build 5.0.3805 are affected by these
vulnerabilities. 

Supersedes :

http://www.microsoft.com/technet/security/bulletin/ms02-052.mspx

See :
http://www.microsoft.com/technet/security/bulletin/ms02-069.mspx

Also Note: Requires full registry access (Administrator)
to run the test.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q329077, Flaw in Microsoft VM JDBC";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SECNAP Network Security, LLC");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl"); 
 script_require_keys("SMB/registry_full_access", "SMB/WindowsVersion");
 script_exclude_keys("SMB/samba");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");
if(!version)exit(0);

if ( hotfix_check_sp(xp:2, win2k:4) <= 0 ) exit(0);

version = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{08B0E5C0-4FCB-11CF-AAA5-00401C608500}/Version");
if (!version) exit(0);

# should be "5,00,3807,0";
v = split(version, sep:",", keep:FALSE);
if ( int(v[0]) < 5 ||
     ( int(v[0]) == 5 && int(v[1]) == 0 && int(v[2]) < 3809) )
{
 if ( hotfix_missing(name:"810030") > 0 )
   security_hole(port);
}
