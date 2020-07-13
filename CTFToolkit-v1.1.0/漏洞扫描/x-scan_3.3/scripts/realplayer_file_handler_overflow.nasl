#
#  (C) Tenable Network Security
#
#
# 
# - Thanks to stbjr -

if(description)
{
 script_id(12044);
 script_bugtraq_id(9580);
 
 script_version("$Revision: 1.2 $");

 name["english"] = "RealPlayer File Handler Code Execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has RealPlayer installed. There is a flaw in the remote 
version which may allow an attacker to execute arbitrary code on the 
remote host, with the privileges of the user running RealPlayer.

To do so, an attacker would need to send a corrupted RMP file to
a remote user and have him open it using RealPlayer.

Solution : See http://service.real.com/help/faq/security/040123_player/EN/

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
		
 if(ereg(pattern:"6\.0\.12\.([0-9]|[0-9][0-9]|[0-5][0-9][0-9]|6[0-8][0-9])$", string:version))
 		security_hole(port);		
}
