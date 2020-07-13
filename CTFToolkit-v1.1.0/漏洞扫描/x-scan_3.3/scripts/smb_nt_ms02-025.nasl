#
# This script was written by Michael Scheidell <scheidell at secnap.net>
# Copyright 2002 SECNAP Network Security, LLC.

#
if(description)
{
 script_id(11143);
 script_bugtraq_id(4881);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2002-0368");
 name["english"] = "Exchange 2000 Exhaust CPU Resources (Q320436)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Malformed Mail Attribute can Cause Exchange 2000 to Exhaust CPU
Resources (Q320436)

Impact of vulnerability: Denial of Service

Affected Software: 

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical

See
http://www.microsoft.com/technet/security/bulletin/ms02-025.mspx

(note: requires admin level netbios login account to check)

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q320436, DOS on Exchange 2000";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include ("smb_hotfixes.inc");


server = hotfix_check_nt_server();
if (!server) exit (0);

version = get_kb_item ("SMB/Exchange/Version");
if (!version || (version != 60)) exit (0);

sp = get_kb_item ("SMB/Exchange/SP");
if (sp && (sp >= 3)) exit (0);

if (hotfix_missing (name:"320436") > 0 )
  security_hole(get_kb_item("SMB/transport"));
