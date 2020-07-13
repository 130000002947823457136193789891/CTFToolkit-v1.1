#
# (C) Tenable Network Security
#
if(description)
{
 script_id(11952);
 script_version("$Revision: 1.5 $");

 name["english"] = "FlashPlayer files reading";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of flash player older than 7.0.19.0.

This version can be abused in conjunction with several flaws in the web
browser to read local files on this system.

To exploit this flaw, an attacker would need to lure a user of this system
into visiting a rogue website containing a malicious flash applet.

Solution : Upgrade to version 7.0.19.0 or newer.
See also : http://www.macromedia.com/devnet/security/security_zone/mpsb03-08.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of the remote flash plugin";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("flash_player_overflows.nasl");
 script_require_keys("MacromediaFlash/version");
 exit(0);
}



include("smb_func.inc");
version = get_kb_item("MacromediaFlash/version");
if ( ! version ) exit(0);

if(ereg(pattern:"WIN (([0-6],.*)|(7,0,(([0-9]|1[0-8]?),0))).*", string:version))security_hole(kb_smb_transport());
