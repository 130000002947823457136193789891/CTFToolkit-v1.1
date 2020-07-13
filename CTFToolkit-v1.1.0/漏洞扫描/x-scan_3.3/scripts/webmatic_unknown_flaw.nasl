#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14382);
 script_bugtraq_id(11045);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "WebMatic Security Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running WebMatic, a web-based application designed to
generate websites.

There is an unknown flaw in the remote version of this software, which was
disclosed by the vendor. The vulnerability type and impact are unknown.

Solution : Upgrade to WebMatic 1.9
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of webmatic";
 
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


foreach dir ( cgi_dirs() )
{
 req = http_get ( item : dir + "/index.php", port:port );
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

#<a href="http://www.webmatic.tk" TARGET="NEW">Powered by: Webmatic 1.9</a></div></td>
 if ( "Webmatic" >< res && 
      egrep(pattern:".*http://www\.webmatic\.tk.*Powered by: Webmatic (0\.|1\.[0-8][^0-9]", string:res) )
	{
	security_warning( port );
	exit(0);
 	}
}
