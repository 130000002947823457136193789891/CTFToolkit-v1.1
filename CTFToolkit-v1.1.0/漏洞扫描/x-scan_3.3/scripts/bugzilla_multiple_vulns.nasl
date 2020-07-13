#
# (C) Tenable Network Security
#


if(description)
{
 script_id(13635);
 script_cve_id(
   "CAN-2004-0702",
   "CAN-2004-0703",
   "CAN-2004-0704",
   "CAN-2004-0705",
   "CAN-2004-0706",
   "CAN-2004-0707"
 );
 script_bugtraq_id(10698);
 script_version ("$Revision: 1.4 $");

 name["english"] = "Bugzilla Multiple Flaws (2)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Bugzilla bug tracking system, according to its version number, is 
vulnerable to various flaws :

- An administratrator may be able to execute arbitrary SQL commands on the
remote host.

- There are instances of information leaks which may let an attacker know
the database password (under certain circumstances, 2.17.x only) or obtain
the names of otherwise hidden products.

- A user with grant membership privileges may escalate his privileges
and belong to another group.
 
- There is a cross site scripting issue in the administrative web interface.

- Users passwords may be embedded in URLs (2.17.x only).

Solution : Upgrade to 2.16.6 or 2.18rc1.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of bugzilla";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("bugzilla_detect.nasl");
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

version = get_kb_item(string("www/", port, "/bugzilla/version"));
if(!version)exit(0);


if(ereg(pattern:"(1\..*)|(2\.(16\.[0-5]|17\.))[^0-9]*$",
       string:version))security_warning(port);
