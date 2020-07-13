#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10903);
 script_version("$Revision: 1.7 $");
 name["english"] = "Users in the 'System Operator' group";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script displays the names of the users that
are in the 'system operator' group.

You should make sure that only the proper users
are member of this group.

Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Lists the users that are in special groups";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : User management";
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports (139,445);
 exit(0);
}
 
include ("smb_func.inc");

function parse_lsasid (sid)
{
 local_var ret;

 ret = NULL;
 ret[0] = get_dword(blob:sid, pos:0);
 ret[1] = substr(sid,4,strlen(sid)-1);

 return ret;
}

sid = raw_string (0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x25,0x02,0x00,0x00);

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

group = NULL;

lsa = LsaOpenPolicy (desired_access:0x20801);
if (!isnull(lsa))
{
 sids = NULL;
 sids[0] = sid;
 names = LsaLookupSid (handle:lsa, sid_array:sids);
 if (!isnull(names))
 {
  group = parse_lsasid(sid:names[0]);
 }
 
 LsaClose (handle:lsa);
}

if (isnull(group))
{
 NetUseDel();
 exit(0);
}

members = NetLocalGroupGetMembers (group:group[1]);

foreach member ( members )
{
  member = parse_lsasid(sid:member);
  report = report + string(". ", member[1], " (", SID_TYPE[member[0]], ")\n");
}

NetUseDel();

if( report )
{
 data = 
 string("The following users are in the 'System Operator' group :\n\n", report,
 "\n\n", "You should make sure that only the proper users are member of this
 group\n", "Risk factor : Low");
 
 security_note(port:port, data:data);
}
