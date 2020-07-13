
#
# This script was written by Noam Rathaus <noamr@beyondsecurity.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(15716);
 script_version("$Revision: 1.2 $");

 name["english"] = "Nortel Web Management Default Username and Password (ro/ro)";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to access the remote network device's web management console
by providing it with a its default username and password (ro/ro). This username
can be also used when accessing the device via SSH, telnet, rlogin, etc.

Solution : Set a strong password for this account or disable it
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of default username and password";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

res = http_get_cache(item:"/", port:port);
if(res == NULL) exit(0);

# Sample response:
#
#<input type="hidden" name="encoded">
#<input type="hidden" name="nonce" value="
#0a7731a40000002a
#">
#<input type="submit" name="goto" value="Log On" onClick="encode()">


nonce = strstr(res, string('<input type="hidden" name="nonce" value="'));
nonce = strstr(nonce, string("\r\n"));
nonce -= string("\r\n");
nonce = nonce - strstr(nonce, string("\r\n"));
if(nonce)
{
 pre_md5 = string("ro:ro:", nonce);
 md5 = hexstr(MD5(pre_md5));
 req = string("POST / HTTP/1.1\r\n",
"Host: ", get_host_name(), ":", port, "\r\n",
"User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7) Gecko/20040928 Firefox/0.9.3\r\n",
"Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n",
"Accept-Language: en-us,en;q=0.5\r\n",
"Accept-Encoding: gzip,deflate\r\n",
"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
"Connection: close\r\n",
"Content-Type: application/x-www-form-urlencoded\r\n",
"Content-Length: ");

 content = string("encoded=ro%3A", md5, "&nonce=", nonce, "&goto=Log+On&URL=%2F");
 
 req = string(req, strlen(content), "\r\n\r\n",
              content);
 res2 = http_keepalive_send_recv(port:port, data:req, bodyonly:0);
 if(res2 == NULL) exit(0);
 if ((res2 >< "Set-Cookie: auth=") && (res2 >< "logo.html")) security_hole(port:port);
}
