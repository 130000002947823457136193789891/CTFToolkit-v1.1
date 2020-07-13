#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Modified by John Lampe...j_lampe@bellsouth.net to add "open service" call and
# add 2 more files to look for

if(description)
{
 script_id(10077);
 script_version ("$Revision: 1.33 $");
 script_cve_id("CAN-2000-0114");
 name["english"] = "Microsoft Frontpage exploits";
 name["francais"] = "Exploits Microsoft Frontpage";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "
The remote web server appears to be running with the Frontpage extensions.
Frontpage allows remote web developers and administrators to modify web
content from a remote location.  While this is a fairly typical scenario
on an internal Local Area Network, the Frontpage extensions should not
be available to anonymous users via the Internet (or any other untrusted
3rd party network).";


 desc["francais"] = "
Le serveur web distant semble tourner avec
des extensions Frontpage.

Vous devriez vérifier votre configuration puisque
de nombreux problèmes de sécurité sont liés a la mauvaise
configuration de ces extensions.

Facteur de risque : Elevé si votre fichier de configuration
n'est pas bien fait";


 script_description(english:desc["english"], francais:desc["francais"]);

 summary["english"] = "Checks for the presence of Microsoft Frontpage extensions";
 summary["francais"] = "Vérifie la présence des extensions Frontpage";
 script_summary(english:summary["english"], francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
                francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/no404") ) exit(0);

req = string("POST /_vti_bin/shtml.dll/_vti_rpc HTTP/1.0\r\n");
req = req + string("Connection: Keep-Alive\r\nDate: Mon, 23 Mar 2003 00:00:15 GMT\r\n");
req = req + string("Accept: */*\r\nHost: ", get_host_ip(),"\r\n","User-Agent: MSFrontPage/4.0\r\n");
req = req + string("Content-Length: 58\r\nContent-Type: application/x-www-form-urlencoded\r\n");
req = req + string("MIME-Version: 1.0\r\nX-Vermeer-Content-Type: application/x-www-form-urlencoded\r\n\r\n");
req = req + string("method=open+service%3a3%2e0%2e2%2e1105&service%5fname=%2f\r\n");
soc = open_sock_tcp(port);
if (soc) {
    send(socket:soc, data:req);
        r = http_recv(socket:soc);
        if(!egrep(pattern:"^<li>msg=The user '\(unknown\)'", string:r) &&
	   egrep(pattern:".*x-vermeer-rpc*", string:r)) {

	     msg = egrep(pattern:".*<li>msg=.*'.*'.*'open service'.*", string:r);
	     if ( msg )
	     {	
	      user = ereg_replace(pattern:".*<li>msg=.*'(.*)'.*'open service'.*", string:r, replace:"\1");
              myreport = string("The remote frontpage server leaks information regarding the name anonymous user\r\n");
             myreport += string("By knowing the name of the anonymous user, more sophisticated attacks may be launched\r\n");
             myreport += string("We could gather that the name of the anonymous user is : ", user,"\r\n\r\nSolution: None\r\nRisk Factor: Low\r\n");
             set_kb_item(name:"www/frontpage", value:TRUE);
             security_note(port:port, data:myreport);
	    }
        }
        close(soc);
}




file[0] = "/_vti_bin/_vti_adm/admin.dll";
file[1] = "/_vti_bin/_vti_aut/author.dll";
file[2] = "/_vti_bin/shtml.exe/_vti_rpc";
flag = 1;

for (i=0; file[i]; i = i + 1) {
    flag = is_cgi_installed_ka(item:file[i], port:port);
    if(get_port_state(port)  && flag)
    {
        soc = open_sock_tcp(port);
        if(soc)
        {
            name = string("www/no404/", port);
            no404 = get_kb_item(name);
            str = http_post(item:file[i], port:port);
            send(socket:soc, data:str);
            buf = recv_line(socket:soc, length:1024);
            content = http_recv(socket:soc);
            buf = tolower(buf);
            close(soc);
            if(("http/1.1 200" >< buf)||("http/1.0 200" >< buf))
            {
                if(no404)
                {
                    no404 = tolower(no404);
                    if(no404 >< content)exit(0);
                }
                security_note(port);
                set_kb_item(name:"www/frontpage", value:TRUE);
		exit(0);
            }
         }
    }
        flag = 1;
}



