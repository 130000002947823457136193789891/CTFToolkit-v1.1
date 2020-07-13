# Copyright (C) 2000 - 2004 Net-Square Solutions Pvt Ltd.
# By: Hemil Shah
# Desc: This script will check for the ReadDesign vuln on names.nsf.
if(description)
{
	script_id(12249);
	script_version ("$Revision: 1.3 $");
 	name["english"] = "ReadDesign checker";
 	script_name(english:name["english"]);
	desc["english"] = 
"This plugin checks for ReadDesign vulns on the remote web server.

For more information, see:

https://www.appsecinc.com/Policy/PolicyCheck1520.html

Risk: Medium";
	script_description(english:desc["english"]);
 	summary["english"] = "ReadDesign checker";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2004 Net-Square Solutions Pvt Ltd.");
	family["english"] = "Misc.";
	script_family(english:family["english"]);
	script_dependencie("find_service.nes");
	script_require_ports("Services/www", 80);
	exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

exit(0); # broken

port = get_http_port(default:80);

if(! get_port_state(port))
    exit(0);

if ( get_kb_item("www/no404/" + port) ) exit(0);

dirs[0] = "/names.nsf";
dirs[1] = "/homepage.nsf";
dirs[2] = "/admin.nsf";
dirs[3] = "/admin4.nsf";
dirs[4] = "/smtp.nsf";
dirs[5] = "/reports.nsf";
dirs[6] = "/statmail.nsf";
dirs[7] = "/webadmin.nsf";

report = string("The ReadDesign vulnerability was found on the server.
Specifically, configuration information may be leaked which would aid
an attacker in future exploits\n");



for(i=0; dirs[i]; i++)
{   
	req = string(dirs[i], "/?ReadDesign");
	req = http_get(item:req, port:port);
	res = http_keepalive_send_recv(port:port, data:req);

	if ( res == NULL ) exit(0);

       
        if( ereg(pattern:"HTTP/1.[01] 200", string:res)  )
        {	
	    report = report + string("The following request triggered the vulnerability\n");
	    report = report + string(req, "\nRisk: Medium\n"); 
            report = report + string("See: https://www.appsecinc.com/Policy/PolicyCheck1520.html");
            security_hole(port:port, data:report);            
            exit(0);
        }
}

