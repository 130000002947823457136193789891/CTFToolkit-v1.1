# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if(description)
{
 script_id(15588);
 script_version("$Revision: 1.6 $");
 name["english"] = "Detect Apache HTTPS";
 script_name(english:name["english"]);
 
 desc["english"] = "
Nessus is talking in plain HTTP on a SSL port.
This means that you should enable SSL tests in find_service 
'Preferences', or increase the timeouts if this option is
already set and the plugin missed this port.

Tests will go on in HTTPS on _this_ port. Other might be skipped.

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Web server complains that we are talking plain HTTP on HTTPS port";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english: "Service detection");
 script_dependencie("find_service.nes");
 exit(0);
}

# 

include("misc_func.inc");

banners = get_kb_list("FindService/tcp/*/get_http");
if (COMMAND_LINE)
{
  soc = http_open_socket(443);
  if (! soc) exit(0);
  send(socket: soc, data: 'GET / HTTP/1.0\r\n\r\n');
  banner = recv(socket: soc, length: 65535);
  http_close_socket(soc);
  if (! banner) exit(0);
  banners = make_array(443, banner);  
}
if ( isnull(banners) ) exit(0);

foreach p (keys(banners))
{
# If there are several values, get_kb_item will fork and that's bad.
# However, this only happens when the KB is saved?
  b = banners[p];
  port = ereg_replace(string: p, pattern: ".*/([0-9]+)/.*", replace: "\1");
  port = int(port);
  if (port)
    if (# Apache
        b =~ "<!DOCTYPE HTML .*You're speaking plain HTTP to an SSL-enabled server" ||
        # Webmin
        "Bad Request" >< b && "<pre>This web server is running in SSL mode" >< b)
  {
    security_note(port);
    if (COMMAND_LINE) display("\n **** SSL server detected on ", get_host_ip(), ":", port, " ****\n\n");
    if (service_is_unknown(port: port)) 
      register_service(port: port, proto: "www");
    for (t = ENCAPS_SSLv2; t <= ENCAPS_TLSv1; t ++)
    {
      s = open_sock_tcp(port, transport: t);
      if (s)
      {
        send(socket: s, data: 'GET / HTTP/1.0\r\n\r\n');
        b = recv(socket: s, length: 4096);
        close(s);
        k = "Transports/TCP/"+port;
        if (defined_func("replace_kb_item"))
        {
          replace_kb_item(name: k, value: t);
          if (b)
          {
            replace_kb_item(name: "FindService/tcp/"+port+"/get_http", value: b);
            replace_kb_item(name: "www/banner/"+port, value: b);
          }
        }
        else
        {
          set_kb_item(name: k, value: t);
          if (b)
          {
            set_kb_item(name: "FindService/tcp/"+port+"/get_http", value: b);
            set_kb_item(name: "www/banner/"+port, value: b);
          }
        }
        break;
      }
    }
  }
}

