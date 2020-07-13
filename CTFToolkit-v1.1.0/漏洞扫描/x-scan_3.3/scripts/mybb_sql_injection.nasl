#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16143);
 script_version ("$Revision: 1.2 $");

 script_cve_id("CAN-2005-0282");
 script_bugtraq_id(12161);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"12798");
 }

 name["english"] = "MyBulletinBoard member.php SQL Injection Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running MyBulletinBoard, a PHP-based bulletin board.

The remote version of this software is prone to a SQL injection
vulnerability due to its failure to sanitize user-supplied input to the
avatar upload system via the 'uid' parameter of the 'member.php' script. 
This may allow an attacker to uncover password hashes and thereby gain
access to the application's admin panel. 

See also : http://www.mybboard.com/community/showthread.php?tid=1438
Solution : Replace the 'member.php' script referenced in the URL above.
Risk factor : High";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for SQL injection vulnerability in MyBulletinBoard's member.php script";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
  
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
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
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


foreach dir (cgi_dirs()) {
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/member.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's from MyBulletinBoard...
  if (egrep(string:res, pattern:"Powered by <a href=.*www\.mybboard\.com.*MyBulletinBoard</a>")) {
    # Try to exploit the vulnerability.
    #
    # nb: use an randomly-named table so we can generate a MySQL error.
    rnd_table = string("nessus", rand_str(length:3));
    postdata = string(
      "uid=1'%20UNION%20SELECT%2010000,200,1%20AS%20type%20FROM%20", rnd_table, "%20WHERE%20uid=1%20ORDER%20BY%20uid%20DESC/*"
    );
    req = string(
      "POST ", dir, "/member.php?action=avatar HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see our table name.
    if (
      egrep(
        string:res, 
        pattern:string("mySQL error: 1146<br>Table 'mybb\\.", rnd_table),
        icase:TRUE
      )
    ) {
      security_hole(port);
      exit(0);
    }
  }
}
