#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16335);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "PHP-Fusion Detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script determines if 'PHP-Fusion' is installed on the remote
host and writes its location down in the KB.

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the location of the remote PHP-Fusion";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

report = NULL;

function check(loc)
{
 req = http_get(item:string(loc, "/news.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 #display(r);
 line = egrep(pattern:"Powered by.*PHP-Fusion.*", string:r);
 if (  line )
 {
   version = ereg_replace(pattern:".*PHP-Fusion.*v([0-9]\.[0-9]+) . 200[0-9]-200[0-9].*", string:chomp(line), replace:"\1", icase:TRUE);
   display("version = ", version, "\n");
   if ( loc == "" ) loc = "/";
   set_kb_item(name:"www/" + port + "/php-fusion", value:version + " under " + loc);
   report += ' - ' + version + ' under ' + loc + '\n';
 }
}

foreach dir (make_list(""))
{
 check(loc:dir);
}

if ( report )
{
 report = "
The remote host is running PHP-Fusion, a web content management system
written in PHP. 

The remote web site is running the following version(s) of this software :

" + report + "

Risk Factor : None";
  security_note(port:port, data:report);
}

