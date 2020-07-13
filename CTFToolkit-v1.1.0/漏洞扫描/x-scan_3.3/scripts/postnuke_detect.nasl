#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15721);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "PostNuke Detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running PostNuke, a web content manager written in PHP.
See http://www.postnuke.com for more information.


Risk factor: None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detects the presence of PostNuke";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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

dirs = "";




function check(loc)
{
 req = http_get(item:string(loc, "/index.php?module=Navigation"), port:port);

 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if('PostNuke' >< r && egrep(pattern:"<meta name=.generator. content=.PostNuke", string:r) )
 {
	version_str = egrep(pattern:"<meta name=.generator. content=.PostNuke", string:r);
	version_str = chomp(version_str);
 	version = ereg_replace(pattern:".*content=.PostNuke ([0-9.]*) .*", string:version_str, replace:"\1");
	if ( version == version_str ) version = "unknown";
	if ( loc == "" ) loc = "/";
	set_kb_item(name:"www/" + port + "/postnuke",
		    value:version + " under " + loc );
	
	dirs += " - " + loc + '\n';
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

if ( dirs ) 
{
report = "
The remote host is running PostNuke, a web content manager written in PHP.
See http://www.postnuke.com for more information.

PostNuke is installed under the following location(s) :

" + dirs + "

Risk Factor : None";
 security_note(port:port, data:report);
}

