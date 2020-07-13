#
# This script was written by Noam Rathaus
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11963);
 script_version("$Revision: 1.6 $");
 name["english"] = "Detect SIP Compatible Hosts";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running SIP (Session Initiation Protocol), a protocol
used for Internet conferencing and telephony.

For more information about this protocol, visit http://www.cs.columbia.edu/sip/
";


 script_description(english:desc["english"]);

 summary["english"] = "SIP Detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");
 script_family(english:"Service detection");
 script_require_ports(5060);
 exit(0);
}

include("dump.inc");
include("global_settings.inc");
include("misc_func.inc");
debug = debug_level;

if(islocalhost())exit(0);

myaddr = this_host();
dstaddr = get_host_ip();
returnport = rand() % 65535;

if (debug)
{
 display("returnport: ", returnport, "\n");
}

mystring = string("OPTIONS sip:", get_host_name(), " SIP/2.0\r\nVia: SIP/2.0/UDP ", myaddr, ":", returnport, "\r\nFrom: Test <sip:", myaddr, ":", returnport, ">\r\nTo: <sip:", myaddr, ":", returnport, ">\r\nCall-ID: 12312312@", myaddr, "\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\r\n");

if (debug)
{
 display("mystring: ", mystring, "\n");
}

len = strlen(mystring);

ippkt = forge_ip_packet(ip_hl   :5,
                        ip_v    :4,
                        ip_tos  :0,
                        ip_len  :20,
                        ip_id   :31337,
                        ip_off  :0,
                        ip_ttl  :64,
                        ip_p    :IPPROTO_UDP,
                        ip_src  :myaddr);

udppacket = forge_udp_packet(ip      :ippkt,
                             uh_sport:returnport,
                             uh_dport:5060,
                             uh_ulen :8 + len,
                             data    :mystring);

filter = string("udp and src " , dstaddr , " and dst port ", returnport);
rpkt = send_packet(udppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
if(rpkt)
{
 if (debug)
 {
  display("return packet\n");
 }

 data = get_udp_element(udp:rpkt, element:"data");

 if (debug)
 {
  display("data: ", data, "\n");
 }

 if ("SIP/2.0 " >< data)
 {
  if (egrep(pattern: '^Server:', string: data))
  {
   banner = egrep(pattern: '^Server:', string: data);
   banner -= "Server: ";
   banner -= string("\r\n");
   if (debug)
   {
    display("banner: ", banner, "\n");
   }

   if(!get_kb_item("sip/banner/5060"))
   {
    set_kb_item(name:"sip/banner/5060", value:banner);
   }
  }

report = "The remote host is running SIP (Session Initiation Protocol), a protocol
used for Internet conferencing and telephony.

The banner of the remote service is : " + banner + "

For more information about this protocol, visit http://www.cs.columbia.edu/sip/";
  security_note(port:5060, protocol:"udp", data:report);
  register_service(port: 5060, ipproto: "udp", proto: "sip");
 }
}

