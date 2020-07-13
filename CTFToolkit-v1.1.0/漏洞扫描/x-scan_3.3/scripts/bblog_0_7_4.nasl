#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18188);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(13397, 13398);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15754");
    script_xref(name:"OSVDB", value:"15755");
    script_xref(name:"OSVDB", value:"15756");
  }

  name["english"] = "bBlog <= 0.7.4 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running bBlog, an open source blog software package.

According to its banner, the remote version of this software suffers from 
several vulnerabilities:

  o A SQL Injection Vulnerability
    It is reportedly possible to inject SQL statements through
    the 'postid' parameter of the 'index.php' script.

  o Multiple Cross-Site Scripting Vulnerabilities
    The application fails to properly sanitize user-supplied
    input through the blog entry title field and the comment 
    body text.

Solution : Unknown at this time.
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in bBlog <= 0.7.4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for bBlog.
foreach dir (cgi_dirs()) {
  # Grab the admin index.php -- by default it holds the version number.
  req = http_get(item:string(dir, "/bblog/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's bBlog...
  if ("Welcome to bBlog" >< res || "<h1>bBlog</h1>" >< res) {
    if (egrep(string:res, pattern:"^bBlog \.([0-6].+|7\.[0-4])</a> &copy; 200")) {
      security_warning(port);
      exit(0);
    }
  }
}
