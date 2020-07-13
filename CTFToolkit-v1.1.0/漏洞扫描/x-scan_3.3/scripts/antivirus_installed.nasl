#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16193);
 script_version("$Revision: 1.2 $");
 name["english"] = "Anti Virus Check";
 script_name(english:name["english"]);
 desc["english"] = "
This plugin checks that the remote host has an Antivirus installed.

Risk factor : None";

 script_description(english:desc["english"]);
 summary["english"] = "Checks that the remote has an Antivirus installed."; 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security"); 
 family["english"] = "Windows"; 
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl", "mcafee_installed.nasl", "nav_installed.nasl", "trendmicro_installed.nasl"); 
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access","SMB/transport");
 script_require_ports(139, 445); 
 exit(0);
}
include("smb_func.inc");

#==================================================================#
# Section 1. Report                                                #
#==================================================================#

port = kb_smb_transport();
if(!port)port = 139;

#
# If remote host has mcafee antivirus
#

mcafee = get_kb_item ("Antivirus/McAfee/installed");

if ( mcafee )
{
  description = get_kb_item ("Antivirus/McAfee/description");
  if (description)
    security_note (port:port, data:description);

  exit (0);
}



#
# If remote host has norton antivirus
#

nav = get_kb_item ("Antivirus/Norton/installed");

if ( nav )
{
  description = get_kb_item ("Antivirus/Norton/description");
  if (description)
    security_note (port:port, data:description);

  exit (0);
}



#
# If remote host has trendmicro antivirus
#

trendmicro = get_kb_item ("Antivirus/TrendMicro/installed");

if ( trendmicro )
{
  description = get_kb_item ("Antivirus/TrendMicro/description");
  if (description)
    security_note (port:port, data:description);

  exit (0);
}
