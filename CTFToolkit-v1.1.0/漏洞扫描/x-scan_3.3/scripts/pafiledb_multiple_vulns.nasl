#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(17329);
  script_version("$Revision: 1.3 $");

  script_cve_id(
    "CAN-2004-1219",
    "CAN-2004-1551",
    "CAN-2005-0326",
    "CAN-2005-0327",
    "CAN-2005-0723",
    "CAN-2005-0724"
  );
  script_bugtraq_id(7183, 8271, 10229, 11817, 11818, 12758, 12788, 13967);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"5695");
    script_xref(name:"OSVDB", value:"5695");
    script_xref(name:"OSVDB", value:"12263");
    script_xref(name:"OSVDB", value:"12264");
    script_xref(name:"OSVDB", value:"12265");
    script_xref(name:"OSVDB", value:"12266");
    script_xref(name:"OSVDB", value:"13494");
    script_xref(name:"OSVDB", value:"13495");
    script_xref(name:"OSVDB", value:"14684");
    script_xref(name:"OSVDB", value:"14685");
    script_xref(name:"OSVDB", value:"14686");
    script_xref(name:"OSVDB", value:"14687");
    script_xref(name:"OSVDB", value:"14688");
  }
 
  script_name(english:"Multiple Vulnerabilities in paFileDB 3.1 and older (2)");

  desc["english"] = "
According to its version number, the remote host is running paFileDB
version 3.1 or older.  These versions are prone to a wide variety of
vulnerabilities, including :

  o SQL Injection Vulnerability
    Due to a failure to properly sanitize user input via the 
    parameters 'id' and 'rating' to the 'rate.php' script, a
    remote attacker can affect database queries by injecting
    arbitrary SQL statements.

  o Arbitrary File Upload And Execution Vulnerability
    The script 'team/file.php' (and possible others) does not
    check for a valid session before accepting uploaded files.
    An attacker can take advantage of this flaw to upload files 
    with arbitrary code and then execute them directly through
    the web server with the permissions of the web server user.

  o ID Variable Cross-Site Scripting Vulnerability
    Due to a failure to properly sanitize user input via the 
    parameter 'id' to the 'category.php' script, a remote attacker 
    can potentially cause arbitrary script code to be executed by 
    a user's browser in the context of the vulnerable site 
    resulting in theft of authentication cookies and other such 
    attacks.

  o Path Disclosure Vulnerabilities
    If PHP on the remote host is configured with 'display_error' 
    enabled, an attacker can learn the physical path of the 
    paFileDB installation by sending a malformed request to one 
    of the scripts 'admins.php', 'category.php', or 'team.php'
    or by requesting various include scripts directly.

  o Password Hash Disclosure Vulnerability
    If paFileDB is configured to authenticate by sessions rather 
    than cookies (cookies are recommended and used by default), 
    anyone can potentially retrieve the MD5 password hash of
    logged in users, including the administrator, by retrieving
    the appropriate file from the 'sessions' directory. Knowing
    the password hash may allow an attacker to perform a brute
    force attack on the password.

  o Arbitrary PHP Code Execution Vulnerability
    An attacker may be able to execute arbitrary PHP code in the
    context of the web server user due to the failure of the
    script 'pafiledb.php' to properly sanitize the parameter
    'action'.

  o Multiple Remote Cross Site Scripting Vulnerabilities
    Due to a failure of the function 'jumpmenu' in the file
    'functions.php' to sanitize the 'pageurl' variable, a
    remote attacker can potentially cause arbitrary script
    code to be executed by a user's browser in the context
    of the vulnerable site resulting in theft of authentication
    cookies and other such attacks.

  o Multiple SQL Injection And Cross-Site Scripting Vulnerabilities
    Due to a failure to properly sanitize user input via the 
    parameters 'start' and 'sortby' to the 'category.php' and 
    'viewall.php' scripts, a remote attacker can modify the 
    logic of database queries made by the software using SQL 
    injection and can potentially cause arbitrary script code
    to be executed by a user's browser in the context of the 
    vulnerable site.

Solution : None at this time. 

Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in paFileDB 3.1 and Older";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("pafiledb_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try various SQL injection attacks.
  exploits = make_list(
    "/pafiledb.php?action=viewall&start='&sortby=rating",
    "/pafiledb.php?action=category&start='&sortby=rating"
  );
  foreach exploit (exploits) {
    req = http_get(item:string(dir, exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);

    # It's a problem if MySQL encountered a syntax error.
    if (egrep(string:res, pattern:"MySQL Returned this error.+ error in your SQL syntax")) {
      security_warning(port);
      exit(0);
    }
  }
}
