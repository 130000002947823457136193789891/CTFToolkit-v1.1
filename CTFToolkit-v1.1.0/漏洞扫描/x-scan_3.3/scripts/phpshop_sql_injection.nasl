#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: JeiAr [security@gulftech.org]
# Subject: phpShop Vulnerabilities
# Date: Friday 16/01/2004 03:14
#
#
# changes by rd:
# - language-insensitive egrep() matching
# - description
#

if(description)
{
  script_id(12022);
  script_bugtraq_id(9437);
  script_version("$Revision: 1.4 $");
  name["english"] = "Multiple phpShop Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running phpShop, a PHP-based e-commerce application and 
PHP development framework. 

Multiple vulnerabilities have been discovered in this product, which may
allow  a remote attacker to send arbitrary SQL commands to the remote database,
or to insert malicious HTML and/or JavaScript into existing pages.

Solution : Upgrade to the latest version of this CGI suite 
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect phpShop SQL Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/?page=shop/cart&func=cartAdd&product_id='"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 find = string("You have an error in your SQL syntax near ");
 find = ".*SQL.*item_enquiry_details.*auth=a";
 if (egrep(pattern:find, string:res))
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs()) check_dir(path:dir);
