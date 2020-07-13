#
# Noam Rathaus

if(description)
{
 script_id(12638);
 script_version("$Revision: 1.5 $");
 
 name["english"] = "DistCC Detection";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
distcc is a program to distribute builds of C, C++, Objective C or 
Objective C++ code across several machines on a network.  
distcc should always generate the same results as a local build, is simple 
to install and use, and is often two or more times faster than a local compile.

distcc by default trusts its clients completely that in turn could
allow a malicious client to execute arbitrary commands on the server.

For more information about DistCC's security see:
http://distcc.samba.org/security.html

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect the presence of DistCC";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

 script_family(english:"Service detection");
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/unknown");
 exit(0);
}

include("misc_func.inc");
include('global_settings.inc');


if ( thorough_tests )
{
 port = get_kb_item("Services/unknown");
 if ( known_service(port:port) ) exit(0);
 if ( ! port ) port = 3632;
}
else port = 3632;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 { 
  req = string("DIST00000001", 
               "ARGC00000008",
               "ARGV00000002","cc",
               "ARGV00000002","-g",
               "ARGV00000003","-O2",
               "ARGV00000005","-Wall",
               "ARGV00000002","-c",
               "ARGV00000006","main.c",
               "ARGV00000002","-o",
               "ARGV00000006","main.o");

  send(socket:soc, data:req);

  req = string("DOTI0000001B", "int main()\n{\n return(0);\n}\n");

  send(socket:soc, data:req);

  response = recv(socket:soc, length:255);
#  display("response: ", response, "\n");

  if ("DONE00000" >< response)
  {
   register_service(port:port, proto:"distccd");
   security_hole(port);
  }
 }
}

