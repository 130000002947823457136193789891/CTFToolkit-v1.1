#
#  (C) Tenable Network Security
#

if(description)
{
 script_id(14278);
 script_bugtraq_id(10934, 10518);
 
 script_version("$Revision: 1.3 $");

 name["english"] = "RealPlayer multiple remote overflows";

 script_name(english:name["english"]);
 
 desc["english"] = "
According to it's version number, the version of Realplayer is
vulnerable to several remote overflows.  

Realplayer is a multimedia player. 

An attacker, exploiting this flaw, would need to be able to coerce
a local user into visiting a malicious URL or downloading a malicious
realplayer media file which, upon execution, would execute code with
the privileges of the local user.

Solution : See http://service.real.com/help/faq/security/

The following versions are reported to be vulnerable:
Real Networks RealOne Player 6.0.11 .872
Real Networks RealOne Player 6.0.11 .868
Real Networks RealOne Player 6.0.11 .853
Real Networks RealOne Player 6.0.11 .841
Real Networks RealOne Player 6.0.11 .830
Real Networks RealOne Player 6.0.11 .818
Real Networks RealOne Player Gold for Windows 6.0.10 .505

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
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/RealNetworks/RealPlayer/Version");
if ( version )
 {
 set_kb_item(name:"SMB/RealPlayer/Version", value: version );
 if(ereg(pattern:"6\.0\.1(1\.(872|868|853|841|830|818)|0\.505)", string:version))
 		security_hole(port);
 else if(ereg(pattern:"6\.0\.10\.505*", string:version))
 		security_hole(port);
}
