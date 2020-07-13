#
# Copyright (C) 2005 Secure Computer Group. University of A Coruna
#
# This script was written by Javier Munoz Mellid <jm@udc.es>
#
# This script is released under the GNU GPL v2
#


if(description)
{
 script_id(18185);
 script_bugtraq_id(13458);
 script_cve_id("CAN-2005-1062", "CAN-2005-1063");
 script_version("$Revision: 1.1 $");

 name["english"] = "Kerio Winroute Firewall < 6.0.11";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host appears to be running a version of
Kerio Winroute Firewall which is older than 6.0.11

The remote software is vulnerable to denial of
services (DoS) and brute-force attacks.

An attacker, exploiting this flaw, will be able to
perform a DoS and/or crack user's passwords.

Solution : Ensure that you are running a patched or
more recent version of this software.

Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Determines if Kerio Winroute Firewall is vulnerable to brute-force attacks and DoS";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Javier Munoz Mellid");
 family["english"] = "Misc.";
 script_family(english:family["english"]);

 script_require_ports(44333);
 exit(0);
}

function kwf_isWeakAdminProtocol(port)
{

  soc = open_sock_tcp(port, transport: ENCAPS_TLSv1);

  if (!soc) return 0;

  vuln = 1;

  for(i=0;i<5;i=i+1) {

        s = raw_string(0x01);
        send(socket:soc, data: s);

        if (!soc) vuln = 0;

        r = recv(socket: soc, length: 16);

        if (isnull(r)||(strlen(r)!=2)||(ord(r[0])!=0x01)||(ord(r[1])!=0x00))
        {

                vuln = 0;
                break;

        }

  }

  close(soc);

  if (vuln)
        return 1;
  else
        return 0;
}

port = 44333;           # default kwf port

if (! get_port_state(port)) exit(0);

if (kwf_isWeakAdminProtocol(port)) security_hole(port);

exit(0);

