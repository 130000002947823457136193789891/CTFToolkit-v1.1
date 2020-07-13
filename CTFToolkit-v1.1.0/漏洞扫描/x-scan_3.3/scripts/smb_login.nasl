#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10394);
 script_bugtraq_id(494, 990, 11199);
 script_version ("$Revision: 1.72 $");
 script_cve_id("CAN-1999-0504", "CAN-1999-0506", "CVE-2000-0222", "CAN-1999-0505", "CAN-2002-1117");
 name["english"] = "SMB log in";
 name["francais"] = "Login SMB";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
This script determines if the remote host has NULL sessions enabled, and 
if the administrator account has a password set.

Reference : http://support.microsoft.com/support/kb/articles/Q143/4/74.ASP
Reference : http://support.microsoft.com/support/kb/articles/Q246/2/61.ASP";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to log into the remote host";
 summary["francais"] = "Essaye de se logguer dans l'hote distant";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 - 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "cifs445.nasl", "find_service.nes", "logins.nasl");
 if ( NASL_LEVEL >= 2202 ) script_dependencies("kerberos.nasl");
 script_require_keys("SMB/name", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

port = kb_smb_transport();
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);

function login(lg, pw, dom)
{ 
 local_var r, soc;

 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);

 session_init(socket:soc, hostname:name);
 r = NetUseAdd(login:lg, password:pw, domain:dom, share:"IPC$");
 NetUseDel();

 if ( r == 1 )
  return TRUE;
 else
  return FALSE;
}


name = kb_smb_name();
if(!get_port_state(port))exit(0);


user_login =  string(get_kb_item("SMB/login_filled"));
user_password = string(get_kb_item("SMB/password_filled"));
if(!strlen(user_password)) user_password = "";
user_domain = string(get_kb_item("SMB/domain_filled"));

smb_domain = string(get_kb_item("SMB/workgroup"));

if ( user_domain )
	smb_domain = user_domain;

if (smb_domain)
{
 smb_domain = ereg_replace(pattern:"(.*) *$", string:smb_domain, replace:"\1");
}

hole = 0;
rand_lg = string ( "nessus", rand(), rand(), rand() ); 
rand_pw = string ( "nessus", rand(), rand(), rand() );


valid_logins   = make_list();
valid_passwords = make_list();



if ( login(lg:NULL, pw:NULL, dom:NULL) == TRUE )
 null_session = TRUE;
else
 null_session = FALSE;

if ( ( login(lg:"administrator", pw:NULL, dom:NULL) == TRUE ) && ( session_is_guest() == 0 ) )
 admin_no_pw = TRUE;
else
 admin_no_pw = FALSE;

if ( ( login(lg:rand_lg, pw:rand_pw, dom:NULL) == TRUE ) )
{
 any_login = TRUE;
 set_kb_item(name:"SMB/any_login", value:TRUE);
}
else
 any_login = FALSE;

if ( user_login )
{
 if ((login(lg:user_login, pw:user_password, dom:smb_domain) == TRUE )  && ( session_is_guest() == 0 ))
  supplied_login_is_correct = TRUE;
 else
  supplied_login_is_correct = FALSE;
}
else 
  supplied_login_is_correct = FALSE;


if ( null_session || supplied_login_is_correct || admin_no_pw || any_login )
{
 if ( null_session != 0 )
  report = string("- NULL sessions are enabled on the remote host\n");

 if ( supplied_login_is_correct )
 {
  if ( ! user_password ) user_password = "";
  if ( ! user_domain ) user_domain = "";

  set_kb_item(name:"SMB/login", value:user_login);
  set_kb_item(name:"SMB/password", value:user_password);
  set_kb_item(name:"SMB/domain", value:user_domain);
  report += string("- The SMB tests will be done as '", user_login, "'/'******'\n");
 }

 if ( admin_no_pw && !any_login)
 {
  report += string("- The 'administrator' account has no password set\n");
  hole = 1;
  if ( supplied_login_is_correct == FALSE )
  {
  set_kb_item(name:"SMB/login", value:"administrator");
  set_kb_item(name:"SMB/password", value:"");
  set_kb_item(name:"SMB/domain", value:"");
  }
 }

 if ( any_login )
 {
  report += string("- Remote users are authenticated as 'Guest'\n");
  if (( supplied_login_is_correct == FALSE ) && ( admin_no_pw == 0 ))
  {
  set_kb_item(name:"SMB/login", value:rand_lg);
  set_kb_item(name:"SMB/password", value:rand_pw);
  set_kb_item(name:"SMB/domain", value:"");
  }
 }

 if (null_session)
 {
  if (( supplied_login_is_correct == FALSE ) && ( admin_no_pw == 0 ) && ( any_login == FALSE ))
  {
  set_kb_item(name:"SMB/login", value:"");
  set_kb_item(name:"SMB/password", value:"");
  set_kb_item(name:"SMB/domain", value:"");
  }
 }

 if ( hole )
   security_hole(port:port, data:report);
 else
   security_note(port:port, data:report);
}
