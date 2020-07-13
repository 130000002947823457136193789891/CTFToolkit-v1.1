#
# This script was written by Noam Rathaus
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11965);
 script_version("$Revision: 1.2 $");
 name["english"] = "SIP Express Router Register Buffer Overflow";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running a SIP Express Router.

A bug has been found in the remote device which may allow an attacker to
crash this device by sending a too long contact list in REGISTERs.

Solution: Upgrade to version 0.8.11 or use the patch provided at:
http://www.iptel.org/ser/security/secalert-002-0_8_10.patch

For additional details see: http://www.iptel.org/ser/security/

Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "SER Register Buffer Overflow";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("sip_detection.nasl");
 script_require_ports(5060);
 exit(0);
}

banner = get_kb_item("sip/banner/5060");

if ( ! banner ) exit(0);

# Sample: Sip EXpress router (0.8.12 (i386/linux))

if (egrep(pattern:"Sip EXpress router .(0\.[0-7]\.|0\.8\.[0-9]|0\.8\.10) ", string:banner, icase:TRUE))
{
 security_note(port:5060, protocol:"udp");
}

