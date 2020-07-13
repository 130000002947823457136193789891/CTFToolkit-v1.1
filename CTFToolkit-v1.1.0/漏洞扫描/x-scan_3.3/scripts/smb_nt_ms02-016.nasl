#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(10945);
 script_bugtraq_id(4438);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0051");
 name["english"] = "Opening Group Policy Files (Q318089)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Windows 2000 allows local users to prevent the application
of new group policy settings by opening Group Policy files
with exclusive-read access.

Attacker could block application of Group Policy

Affected Software: 

Microsoft Windows 2000 Server 
Microsoft Windows 2000 Advanced Server 
Microsoft Windows 2000 Datacenter Server 

See
http://www.microsoft.com/technet/security/bulletin/ms02-016.mspx

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the Group Policy patch (Q318593) is installed";

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

if ( hotfix_check_domain_controler() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q318593") > 0 ) 
	security_warning(get_kb_item("SMB/transport"));

