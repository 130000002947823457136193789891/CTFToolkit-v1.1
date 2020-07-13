#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(10397);
 script_version ("$Revision: 1.21 $");
 name["english"] = "SMB LanMan Pipe Server browse listing";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script obtains the remote host browse
list using the \PIPE\LANMAN transaction pipe

Risk factor : Low"; 

 script_description(english:desc["english"]);
 
 summary["english"] = "Gets the list of remote host browse list";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

function create_list (data)
{
 local_var list, name, i;

 list = NULL;

 foreach server (data)
 {
  name = NULL;
  for (i=0;i<16;i++)
  {
   if (ord(server[i]) == 0)
     break;
   name += server[i];
  }
  list += name + string (" ( os: ", ord(server[16]), ".", ord(server[17]), " )\n"); 
 }

 return list;
}

port = kb_smb_transport();
if(!port)port = 139;

name = kb_smb_name();
if(!name)exit(0);

if(!get_port_state(port))exit(0);

login = kb_smb_login();
pass = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";
	  
dom = kb_smb_domain();
if (!dom) dom = "";
  
soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}

#
# Request the list of shares
#
servers = NetServerEnum (level:SERVER_INFO_101);
NetUseDel ();
if(!isnull(servers))
{
 # decode the list
 browse = create_list(data:servers);
 if(browse)
 {
  # display the list
  res = string("Here is the browse list of the remote host : \n\n");
  res = res + browse;
  res = res + string("\n\nThis is potentially dangerous as this may help the attack\n");
  res = res + string("of a potential hacker by giving him extra targets to check for\n\n");
  res = res + string("Solution : filter incoming traffic to this port\n");
  res = res + string("Risk factor : Low\n");
  security_note(port:port, data:res);
  set_kb_item(name:"SMB/browse", value:browse);
 }
}
