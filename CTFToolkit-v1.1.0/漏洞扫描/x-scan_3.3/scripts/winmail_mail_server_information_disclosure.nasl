#
# (C) Noam Rathaus GPLv2
#

if(description)
{
 script_id(16042);
 script_version("$Revision: 1.1 $");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"12336");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"12337");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"12338");
 
 name["english"] = "Winmail Mail Server Information Disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Winmail Server.

Winmail Server is an enterprise class mail server software system
offering a robust feature set, including extensive security
measures. Winmail Server supports SMTP, POP3, IMAP, Webmail, LDAP,
multiple domains, SMTP authentication, spam protection, anti-virus
protection, SSL/TLS security, Network Storage, remote access,
Web-based administration, and a wide array of standard email options
such as filtering, signatures, real-time monitoring, archiving,
and public email folders. 

Three scripts that come with the program (chgpwd.php, domain.php and user.php) 
allow a remote attacker to disclose sensitive information about the remote host.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an Information Disclosure in Winmail Mail Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 if (debug) { display("loc: ", loc, "\n"); }
 req = http_get(item:string(loc, "/chgpwd.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if (debug) { display("r: [", r, "]\n"); }
 if(("Call to a member function on a non-object in" >< r) && ("Fatal error" >< r) &&
    ("Winmail" >< r) && ("admin" >< r) && ("chgpwd.php" >< r))
 {
 	security_warning(port);
	exit(0);
 }
}

dirs = make_list(cgi_dirs(), "/admin/");

foreach dir (dirs)
{
 check(loc:dir);
}

