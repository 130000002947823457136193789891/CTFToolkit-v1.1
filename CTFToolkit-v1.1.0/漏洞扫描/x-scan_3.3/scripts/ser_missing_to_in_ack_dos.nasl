#
# This script was written by Noam Rathaus
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11964);
 script_version("$Revision: 1.2 $");
 name["english"] = "SIP Express Router Missing To in ACK DoS";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is a SIP Express Router (SER).

The SER product has been found to contain a vulnerability where ACKs
requests without a To header, when SER has been enabled to use the SL module,
can be used to crash the product.

Solution: Upgrade to version 0.8.10.
For additional details see: http://www.cert.org/advisories/CA-2003-06.html
Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "SER Missing To in ACK DoS";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("sip_detection.nasl");
 script_require_ports(5060);
 exit(0);
}

debug = 0;

banner = get_kb_item("sip/banner/5060");
if ( ! banner ) exit(0);
# Sample: Sip EXpress router (0.8.12 (i386/linux))

if (egrep(pattern:"Sip EXpress router \((0\.[0-7]\.|0\.8\.[0-9]) ", string:banner))
{
 security_note(port:5060, protocol:"udp");
}

