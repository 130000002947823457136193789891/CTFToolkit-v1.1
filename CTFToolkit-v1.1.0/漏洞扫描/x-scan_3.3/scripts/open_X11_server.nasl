# To be consistent with the "one plugin = one flaw" principle, 
# I split X.nasl in two parts. This script only process results from 
# X.nasl


if(description)
{
  script_id(15897);
  script_version ("$Revision: 1.1 $");
  script_cve_id("CVE-1999-0526");

  name["english"] = "Open X Server";
  script_name(english:name["english"]);

  desc["english"] = "
An improperly configured X server will accept connections from clients from 
anywhere. This allows an attacker to make a client connect to the X server to 
record the keystrokes of the user, which may contain sensitive information,
such as account passwords.

To solve this problem, use xauth or MIT cookies.

Solution : Use xhost, MIT cookies, and filter incoming TCP connections to this 
port.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "An open X Window System Server is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("X.nasl");
 script_require_ports("Services/X11");
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 exit(0);
}

port = get_kb_item("Services/X11");
if (! port) exit(0);	# or port = 6000 ?
open = get_kb_item("X11/"+port+"/open");
if (! open) exit(0);

ver = get_kb_item("X11/"+port+"/version");
textresult = get_kb_item("X11/"+port+"/answer");
report = string("This X server accepts clients from anywhere. This\n",
	    	"allows an attacker to connect to it and record any of your keystrokes.\n\n",
		"Here is the server version : ", ver, "\n",
		"Here is the server type : ", textresult, "\n\n",
		"Solution : use xauth or MIT cookies to restrict the access to this server\n",
		"Risk factor : High");
			
security_hole(port:port, data:report);	
