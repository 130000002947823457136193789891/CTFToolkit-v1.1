#
# (C) Tenable Network Security
#
#http://supportconnect.ca.com/sc/solcenter/sol_detail.jsp?docid=1&product=ETRID&release=3.0.5&number=10&type=&os=NT&aparno=QO66178&searchID=361777&pos=NT 
if(description)
{
 script_id(18537);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(13017);

 name["english"] = "Computer Associates eTrust Intrusion Detection System Remote Denial of Service";
 
 script_name(english:name["english"]);
 
 desc["english"] = "

The remote host is running Computer Associates eTrust Intrusion Detection
System, a security solution with intrusion detection, antivirus, web
filtering and session monitoring.

The remote version of this software is vulnerable to a Denial of Service
vulnerability in the way it uses 'CPImportKey' function.
An attacker can exploit this issue to crash the remote service by sending
a specially crafted administration packet.

Solution : Upgrade to version 3.0.5.57
See also : http://tinyurl.com/bp367
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if eTrust Intrusion Detection System is vulnerable to a Denial of Service";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencies("etrust_ids.nasl");
 script_require_keys("eTrust/intrusion_detection_system");
 exit(0);
}

vers = get_kb_item ("eTrust/intrusion_detection_system");
if (!vers) exit(0);

vers = split (vers, sep:".", keep:0);

if ( (vers[0] < 3) ||
     ( (vers[0] == 3 ) && (vers[1] == 0) && (vers[2] < 557) ) )
  security_hole (get_kb_item("Services/eTrust-IDS"));
