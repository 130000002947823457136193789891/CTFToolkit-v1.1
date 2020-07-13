#
# This script is (C) Tenable Network Security
#
#




if(description)
{
 script_id(16023);
 script_bugtraq_id(12066);
 script_version ("$Revision: 1.3 $");

 name["english"] = "WordPress Cross-Site Scripting / SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
According to its banner, the remote version of WordPress is vulnerable
to a cross-site scripting attack which may allow an attacker to use the
remote server to steal the cookies of third party users on the remote
site. 

In addition to this, the remote version of this software is vulnerable to a
SQL injection attack which may allow an attacker to execute arbitrary SQL
statements on the remote SQL database.

Solution : Upgrade to WordPress version 1.5.1 or greater.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of WordPress";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("wordpress_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);



# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  # The actual attack requires credentials -> do a banner check
  ver = matches[1];
  if (ver =~ "(0\\.|1\\.([01]|2[^0-9]|2\\.[0-2][^0-9]))") { 
    security_hole(port); 
    exit(0);
  }
}
