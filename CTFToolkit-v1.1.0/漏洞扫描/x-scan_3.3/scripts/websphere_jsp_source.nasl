#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18047);
 script_bugtraq_id(13160);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "IBM WebSphere Application Server source disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote web server disclose the source
code of its JSP pages by requesting the pages with a non-existing
hostname in the HTTP 'Host:' field of the request. 

An attacker may use this flaw to get the source code of your CGIs
and possibly obtain passwords and other relevant information about
this host.

Solution : None at this time
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to read the source of a jsp page";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function check(file, hostname)
{
 req = string("GET " + file + " HTTP/1.1\r\n" +
"Host: " + hostname + "\r\n" + 
"Pragma: no-cache\r\n" +
"User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n" + 
"Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n" + 
"Accept-Language: en\r\n" + 
"Accept-Charset: iso-8859-1,*,utf-8\r\n\r\n");

 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("<%" >< res) return 1;
 return 0;
}

port = get_http_port(default:80);

if(get_port_state(port))
{
 files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
 if(isnull(files))files = make_list("/index.jsp");
 n = 0;
 foreach file (files)
  {
  if(check(file:file, hostname:get_host_name()) == 0)
   {
   if(check(file:file, hostname:"sjfklsjfkldfjklsdfjdlksjfdsljk.foo.")) { security_hole(port); exit(0); }
  }
  n ++;
  if(n > 20)exit(0);
 }
}
