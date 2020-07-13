#
# (C) Noam Rathaus
#
# This script is released under the GPLv2
#

if(description)
{
 script_id(15752);
 script_version("$Revision: 1.3 $");
 script_cve_id(
   "CAN-2004-1506",
   "CAN-2004-1507",
   "CAN-2004-1508",
   "CAN-2004-1509",
   "CAN-2004-1510"
 );
 script_bugtraq_id(11651);
 
 name["english"] = "WebCalendar SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote installation of WebCalendar may allow an attacker to cause
an SQL Injection vulnerability in the program allowing an attacker to
cause the program to execute arbitrary SQL statements. 

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL injection in view_topic.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("webcalendar_detect.nasl");
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
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];
 req = http_get(item:string(loc, "/view_entry.php?id=1'&date=1"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if(egrep(pattern:"You have an error in your SQL syntax", string:r) ||
    egrep(pattern:"SELECT webcal_entry.cal_id FROM webcal_entry", string: r)
   )
 {
 	security_hole(port);
	exit(0);
 }
}
