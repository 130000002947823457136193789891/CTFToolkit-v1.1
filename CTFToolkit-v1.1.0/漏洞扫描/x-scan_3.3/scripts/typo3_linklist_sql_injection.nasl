#
# (C) Tenable Network Security
#
#

if (description) {
  script_id(17272);
  script_version ("$Revision: 1.1 $");

  script_bugtraq_id(12721);

  name["english"] = "Typo3 CMW Linklist Extension SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
 desc["english"] = "
The installation of Typo3 on the remote host is vulnerable to remote
SQL injection attacks through the parameter 'category_uid' used by the
CMW Linklist extension.  By exploiting this flaw, a remote attacker
may be able to uncover sensitive information or even modify existing
data. 

Solution : Upgrade the CMW Linklist extension to version 1.5.0 or
later, or upgrade to a version of Typo3 greater than 3.7.0 when it
becomes available. 

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects SQL injection vulnerability in Typo3 CMW Linklist extension";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("global_settings.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);


# Search for Typo3 in a couple of different locations in addition to 
# cgi_dirs() based on googling for "This website is brought to you 
# by Typo3".
dirs = make_list(cgi_dirs());
xtra_dirs = make_array(
  "/typo3", 1,
  "/site", 1,
  "/cms", 1
);
foreach dir (dirs) {
  # Set value to zero if it's already in dirs.
  if (!isnull(xtra_dirs[dir])) xtra_dirs[dir] = 0;
}
foreach dir (keys(xtra_dirs)) {
  # Add it to dirs if the value is still set.
  if (xtra_dirs[dir]) dirs = make_list(dirs, dir);
}

foreach dir (dirs) {
  # Check if the extension is available.
  #
  # nb: the flaw is in pi1/class.tx_cmwlinklist_pi1.php so check for that.
  req = http_get(item:string(dir, "/typo3conf/ext/cmw_linklist/pi1/class.tx_cmwlinklist_pi1.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);

  # If it is...
  if (res =~ "HTTP/.+ 200 OK") {
    # Grab the main page.
    req = http_get(item:string(dir, "/index.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);

    # Find the Links page.
    #
    # nb: the actual text could be in the native language or even 
    #     set by the administrator making it hard to get a 
    #     robust pattern. :-(
    pat = '<a href="([^"]+)".+(Links</a>|name="links")';
    matches = egrep(pattern:pat, string:buf, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      links = eregmatch(pattern:pat, string:match);
      if (!isnull(links)) {
        links = links[1];
        if (links !~ "^/") links = "/" + links;
        break;
      }
    }

    # Find a single link in the Links page (which should be local).
    if (!isnull(links) && links !~ "^http") {
      req = http_get(item:string(dir, links), port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (res == NULL) exit(0);

      pat = '<A HREF="([^"]+&action=getviewcategory[^"]*">';
      matches = egrep(pattern:pat, string:buf, icase:TRUE);
      foreach match (split(matches)) {
        match = chomp(match);
        link = eregmatch(pattern:pat, string:match);
        if (!isnull(link)) {
          link = link[1];
          break;
        }
      }

      # Try to exploit vulnerability by issuing an impossible request.
      #
      # nb: The fix for the vulnerability evaluates category_uid as an 
      #     integer; thus, it's vulnerable if the result fails to
      #     return any links.
      if (link) {
        exploit = ereg_replace(
          string:link,
          pattern:"&category_uid=([0-9]+)",
          # cause query to fail by tacking " and 1=0 " onto the category_uid.
          replace:"\1%20and%201=0%20"
        );
        req = http_get(item:exploit, port:port);
        res = http_keepalive_send_recv(port:port, data:req);
        if (res == NULL) exit(0);

        # If there aren't any links, there's a problem.
        if (res !~ "&action=getviewclickedlink&uid=") {
          security_warning(port);
          exit(0);
        }
      }
      else {
        if (log_verbosity > 1) {
          if (dir == "") dir = "/";
          display("Can't find a link for Typo3 installed on " + get_host_name() + " under " + dir + "!\n");
        }
      }
    }
    else {
      if (log_verbosity > 1) {
        if (dir == "") dir = "/";
        display("Can't find links page for Typo3 installed on " + get_host_name() + " under " + dir + "!\n");
      }
    }
  }
}
