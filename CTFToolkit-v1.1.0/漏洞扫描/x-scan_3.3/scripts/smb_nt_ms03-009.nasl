#
# written by Bekrar Chaouki - A.D Consulting <bekrar@adconsulting.fr>
#
# Microsoft ISA Server DNS - Denial Of Service

if(description)
{
 script_id(11433);
 script_bugtraq_id(7145);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CAN-2003-0011");

 name["english"] = "Microsoft ISA Server DNS - Denial Of Service (MS03-009)";

 script_name(english:name["english"]);
 
 desc["english"] = "
A flaw exists in the ISA Server DNS intrusion detection application filter.
An attacker could exploit the vulnerability by sending a specially formed 
request to an ISA Server computer that is publishing a DNS server, which 
could then result in a denial of service to the published DNS server.

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-009.mspx

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ISA Server DNS HotFix SP1-256";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 A.D.Consulting");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/WindowsVersion",
		     "SMB/registry_access");
 script_require_ports( 139, 445 );
 exit(0);
}


port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);

fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/256");
if(!fix)security_hole(port);
