#
# (C) Tenable Network Security
#

if (description)
{
 script_id(15967);
 script_cve_id("CAN-2004-1397");
 script_bugtraq_id(11924);
 script_version ("$Revision: 1.3 $");

 script_name(english:"UseModWiki Cross Site Scripting");
 desc["english"] = "
The remote host is using UseModWiki, a wiki CGI written in PERL.

The CGI 'wiki.pl' is vulnerable to a cross-site-scripting issue
that may allow attackers to steal the cookies of third parties.

Solution: Upgrade to a newer version.
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if wiki.pl is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, '/wiki.pl?<script>foo</script>');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if('<script>foo<' >< buf )
   {
    security_warning(port);
    exit(0);
   }

}
