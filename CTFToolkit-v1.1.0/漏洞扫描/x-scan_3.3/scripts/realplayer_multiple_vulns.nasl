#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17254);
 script_bugtraq_id(12697, 12698); 
 script_version("$Revision: 1.2 $");

 name["english"] = "RealPlayer Multiple Remote Overflows";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has the RealPlayer software installed. 

There are several flaws in the remote version of this software which might allow
an attacker to execute arbitrary code and delete arbitrary files on the remote
host.

To exploit these flaws, an attacker would need to send a malformed SMIL or
WAV file to a user on the remote host and wait for him to open it in RealPlayer.

Solution : http://service.real.com/help/faq/security/050224_player/EN/

If you have uninstalled RealPlayer you may wish to delete
the old registry key at SOFTWARE\RealNetworks\RealPlayer.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of RealPlayer";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("realplayer_6011.nasl");
 script_require_keys("SMB/RealPlayer/Version");
 exit(0);
}



version = get_kb_item("SMB/RealPlayer/Version");
if(version)
{
 if(ereg(pattern:"6\.0\.([0-9]\.|1[01]\.).*", string:version))
 		security_hole(port);
		
 if(ereg(pattern:"6\.0\.12\.([0-9]$|[0-9][0-9]$|[0-9][0-9][0-9]$|10([0-4][0-9]|5[0-8]$))", string:version))
 		security_hole(port);

}

