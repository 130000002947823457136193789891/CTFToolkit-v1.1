#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(11774);
 script_bugtraq_id(8034);
 script_version("$Revision: 1.12 $");
 script_cve_id("CAN-2003-0348");
 
 name["english"] = "Windows Media Player Library Access";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
An ActiveX control included with Windows Media Player 9 Series
may allow a rogue web site to gain information about the 
remote host.

An attacker may exploit this flaw to execute arbitrary code on this
host with the privileges of the user running Windows Media Player.

To exploit this flaw, one attacker would need to set up a rogue
web site and lure a user of this host into visiting it.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-021.mspx
 

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Media Player";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms05-009.nasl", "smb_hotfixes.nasl");
 script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");
 script_exclude_keys("SMB/Win2003/ServicePack");


 script_require_ports(139, 445);
 exit(0);
}

if ( get_kb_item("SMB/890261") ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsMediaPlayer");
if(!version)exit(0);

if (!ereg(pattern:"9\,[0-9]\,[0-9]\,[0-9]", string:version))exit(0);

version = get_kb_item("SMB/WindowsVersion");


fix = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/Windows Media Player/wm819639");
if(fix) exit(0);

fix = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/Windows Media Player/wm828026");
if(fix) exit(0);

fix = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/Windows Media Player/Q828026");
if(fix) exit(0);


if("5.2" >< version)
{
  # This is windows 2003
  sp = get_kb_item("SMB/Win2003/ServicePack");
  if(sp)exit(0);
  security_hole(port);
  exit(0);
}

if("5.1" >< version)
{
  # This is windows XP
  sp = get_kb_item("SMB/WinXP/ServicePack");
  if(sp && ereg(pattern:"Service Pack [2-9]", string:sp))exit(0);
  security_hole(port);
  exit(0);
}

if("5.0" >< version)
{
  # This is windows 2000
  sp = get_kb_item("SMB/Win2k/ServicePack");
  if(sp && ereg(pattern:"Service Pack [5-9]", string:sp))exit(0);
  security_hole(port);
  exit(0);
}
