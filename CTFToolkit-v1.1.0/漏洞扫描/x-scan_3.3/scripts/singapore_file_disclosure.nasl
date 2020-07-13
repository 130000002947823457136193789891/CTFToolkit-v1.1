#
# (C) Noam Rathaus
#
# From: "Mr. Anderson" <dt_student@hotmail.com>
# Subject: Singapore - all versions - admin password vuln
# Date: 17.6.2004 01:10

if(description)
{
 script_id(12283);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "Singapore MD5 Administrative Password Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
Singapore is a PHP based photo gallery web application.

Due to inaddequate security settings, the file used to stored the
administrative password is easily accessible, and the MD5 with which
the product protects the password is feasibably crackable.

Solution: Use the web site's ACL to deny access to the file adminusers.csv.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks adminusers.csv presence";
 
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

foreach dir (cgi_dirs())
{
 req = string(dir,"/data/adminusers.csv");
 req = http_get(item:req, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);

 if(egrep(pattern:'admin,.*,"Administrator","Default administrator account"', string:buf)){
 	security_hole(port);
	exit(0);
	}
}

