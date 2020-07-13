#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(10859);
 script_bugtraq_id(959);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-1200");
 
 name["english"] = "SMB get host SID";
 
 script_name(english:name["english"]);
 
 desc["english"] = "

This script emulates the call to LsaQueryInformationPolicy()
to obtain the domain (or host) SID (Security Identifier).

The domain/host SID can then be used to get the list
of users of the domain or the list of local users

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Gets the host SID";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

port = kb_smb_transport();
if(!port)port = 139;

if(!get_port_state(port))exit(0);

name = kb_smb_name();
if(!name)exit(0);

login = kb_smb_login();
pass  = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

dom = kb_smb_domain();
	  
soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}

handle = LsaOpenPolicy (desired_access:0x20801);
if (isnull(handle))
{
  NetUseDel ();
  exit (0);
}

ret = LsaQueryInformationPolicy (handle:handle, level:PolicyAccountDomainInformation);
if (isnull (ret))
{
 LsaClose (handle:handle);
 NetUseDel ();
 exit (0);
}

sid = ret[1];

LsaClose (handle:handle);
NetUseDel ();


if(strlen(sid) != 0)
{
 set_kb_item(name:"SMB/host_sid", value:hexstr(sid));
 str = string("The host Security Identifier (SID) can be obtained remotely. Its value is :\n\n",
	           sid2string(sid:sid), "\n\n",
              "An attacker can use it to obtain the list of the local users of this host\n",
	      "Solution : filter the ports 137-139 and 445\n",
	      "Risk factor : Low\n");
 security_note(data:str, port:port);
}
