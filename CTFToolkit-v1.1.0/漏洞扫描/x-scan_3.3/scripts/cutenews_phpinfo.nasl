#
# (C) Tenable Network Security
#

if(description)
{
 script_version ("$Revision: 1.4 $");
 script_id(11940);
 script_bugtraq_id(9130);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"2880");
 }
 
 name["english"] = "CuteNews debug info disclosure";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running the CuteNews CGI suite.

There is a bug in this suite which may allow an attacker
to force it to call the phpinfo() PHP function by requesting :

	http://example.com/cutenews/index.php?debug

Some of the information that can be garnered from this output
includes:  The username of the user who installed php, if they 
are a SUDO user, the IP address of the host, the web server 
version, The system version(unix / linux), and the root 
directory of the web server.

Solution: Disable CuteNews or upgrade to the newest version
Risk factor: Low";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for the presence of cutenews";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencies("cutenews_detect.nasl", "http_version.nasl");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  req = http_get(item:string(dir, "/index.php?debug"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL ) exit(0);
  if("CuteNews Debug Information:" >< res)
  {
    security_warning(port);
    exit(0);
  }
}

