#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(10395);
 script_version ("$Revision: 1.25 $");
 name["english"] = "SMB shares enumeration";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script connects to the remote host
using a null (or guest) session, and enumerates the
exported shares

Risk factor : Medium"; 

 script_description(english:desc["english"]);
 
 summary["english"] = "Gets the list of remote shares";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl","smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

port = kb_smb_transport();
if(!port)port = 139;

name = kb_smb_name();
if(!name)exit(0);

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

if (get_kb_item("SMB/any_login"))
{
 login = string ("Nessus",rand(),rand(),rand());
 password = string ("Nessus",rand(),rand(),rand());
}
else
{
 login = NULL;
 password = NULL;
}

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:login, password:password, domain:NULL, share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}

#
# Request the list of shares
#
shares = NetShareEnum (level:SHARE_INFO_0);
NetUseDel ();

if(!isnull(shares))
{ 
 # display the list
 res = string("Here is the list of the SMB shares of this host : \n\n");
 foreach share (shares)
   {
   set_kb_item(name:"SMB/shares", value:share);
   res = res + share + '\n';
   } 
 res = res + string("\n\nThis is potentially dangerous as this may help the attack\n");
 res = res + string("of a potential hacker.\n\n");
 res = res + string("Solution : filter incoming traffic to this port\n");
 res = res + string("Risk factor : Medium");
 security_warning(port:port, data:res);
}
else
{
 login = kb_smb_login();
 pass = kb_smb_password();
 dom = kb_smb_domain();
 if ( login ) 
 {
  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  session_init (socket:soc,hostname:name);
  ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
  if (ret != 1) exit (0);
  shares = NetShareEnum (level:SHARE_INFO_0);
  NetUseDel ();
  if ( ! isnull(shares) ) 
  {
    foreach share (shares) set_kb_item(name:"SMB/shares", value:share);
  }
 }
}



