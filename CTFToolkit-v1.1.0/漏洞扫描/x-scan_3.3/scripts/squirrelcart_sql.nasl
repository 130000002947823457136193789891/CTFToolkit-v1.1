#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17652);
 script_cve_id("CAN-2005-0962");
 script_bugtraq_id(12944);
 script_version("$Revision: 1.4 $");
 name["english"] = "SquirrelCart SQL injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running SquirrelCart, a shopping cart program
written in PHP.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host.

SquirrelCart 1.5.5 and prior versions are affected by this flaw.

See also : http://www.squirrelcart.com/support.php
Solution : Upgrade to SquirrelCart 1.6.0 or download a patch from SquirrelCart.com
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


function check(dir)
{
  req = http_get(item:dir + "/store.php?crn=42'&action=show&show_products_mode=cat_click", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if('SELECT Table_2 FROM REL_SubCats__Cats WHERE Table_2 = ' >< buf )
  	{
	security_hole(port);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) check( dir:dir );
