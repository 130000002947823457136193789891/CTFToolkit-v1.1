#
# (C) Noam Rathaus
#
# From: Francisco Alisson <dominusvis@click21.com.br>
# Subject: Artmedic kleinanzeigen include vulnerabilty
# Date: 19.7.2004 05:25

if(description)
{
 script_id(13654);
 script_bugtraq_id(10746);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Artmedic Kleinanzeigen File Inclusion Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Artmedic Kleinanzeigen, an email verifying PHP script,
has been found to contain an external file inclusion vulnerability. 

Impact:
The file inclusion vulnerability allows a remote attacker to include
external PHP files as if they were the server's own, this causing the
product to execute arbitrary code

Solution : None at this time
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Artmedic Kleinanzeigen's PHP inclusion vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (make_list("/kleinanzeigen", "/php/kleinanzeigen", cgi_dirs()))
{
 foreach file (make_list("index.php3", "index.php4"))
 {
  req = string(dir,"/", file, "?id=http://xx./");
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);

  if ( 'ReadFile("http://xx.")' >< buf )
  {
   security_hole(port);
   exit(0);
  }
 }
}

