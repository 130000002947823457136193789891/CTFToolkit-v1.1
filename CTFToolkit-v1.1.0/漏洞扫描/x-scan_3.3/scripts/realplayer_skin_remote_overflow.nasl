#
#  (C) Tenable Network Security
#
#

if(description)
{
 script_id(15789);
 script_cve_id("CAN-2004-1094");
 script_bugtraq_id(11555);
 
 script_version("$Revision: 1.3 $");

 name["english"] = "RealPlayer Skin File Remote Buffer Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has RealPlayer installed. There is a flaw in the remote 
version of this software which may allow an attacker to execute arbitrary 
code on the remote host, with the privileges of the user running RealPlayer.

To do so, an attacker would need to send a corrupted skin file to
a remote user and have him open it using RealPlayer.

Solution : Upgrade to the newest version of this software.

If you have uninstalled RealPlayer you may wish to delete
the old registry key at SOFTWARE\RealNetworks\RealPlayer.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of RealPlayer";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("realplayer_6011.nasl");
 script_require_keys("SMB/RealPlayer/Version");
 exit(0);
}




version = get_kb_item("SMB/RealPlayer/Version");
 
 
if(version)
{
 if(ereg(pattern:"6\.0\.[0-9]\..*", string:version))
 		security_hole(port);
		
 if(ereg(pattern:"6\.0\.1[01]\..*", string:version))
 		security_hole(port);
		
 if(ereg(pattern:"6\.0\.12\.([0-9]|[0-9][0-9]|[0-9][0-9][0-9]|10([0-4][0-9]|5[0-3])$", string:version))
 		security_hole(port);		
}
