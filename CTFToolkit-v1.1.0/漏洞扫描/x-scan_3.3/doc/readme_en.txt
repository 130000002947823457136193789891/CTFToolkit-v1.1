
X-Scan-v3.3 User Manual


1. System requirement: Windows NT4/2000/XP/2003


2. Introduction:

     X-Scan is a general network vulnerabilities scanner for scanning network vulnerabilities for specific IP address scope or stand-alone computer by multi-threading method, plug-ins are supportable. Which X-Scan feature include in the following: service type, remote OS type and version detection, weak user/password pair, and all of the nessus attack scripts combination. For the most known vulnerabilities, the corresponding descriptions and solutions are provided. As to other vulnerabilities, please refer to "Document" and "Vulnerability engine" in www.xfocus.org.
     We provided a simple SDK in X-Scan 3.0 for the purpose of friends can develop plug-ins conveniently. Everyone can download the source code of "nasl for windows", X-Scan plug-in SDK and the sample plug-in code from this link: "http://www.xfocus.net/projects/X-Scan/index.html".


3. Components:

    xscan_gui.exe               --   X-Scan GUI main program
    checkhost.dat               --   plug-ins scheduler
    update.exe                  --   live update main program
    *.dll                       --   the dynamic library files
    readme.txt                  --   X-Scan ReadMe
    /dat/language.ini           --   multi-language config file, language can be switched by setting "LANGUAGE\SELECTED" 
    /dat/language.*             --   multi-language database
    /dat/config.ini             --   current configuration file, being used for save all configuration
    /dat/*.cfg                  --   custom configuration file
    /dat/*.dic                  --   username and password dictionary, being used for searching weak password
    /plugins                    --   being used for storing all plug-ins (whose suffix is .xpn).
    /scripts                    --   being used for storing all nessus attack scripts (whose suffix is .nasl)
    /scripts/desc               --   being used for storing all muti-language description of nessus attack scripts (whose suffix is .desc)
    /scripts/cache              --   being used for caching all nasl scripts (you can delete it at any moment)


4. Preparation:

    X-Scan which is absolutely free can be executed immediately after being decompressed without registration and installation (install WinPCap v3.1 beta4 automatically).


5. GUI program options description:
    
    "Scan range":
    
      "IP address range" - You can input a large range of IP section or a single IP address or domain name, and you can input the range of IP address that be separated by "-" or "," also, for example: "192.168.0.1-20,192.168.1.10-192.168.1.254,192.168.2.1/24". 
    
      "Load host list from file" - If this checkbox is checked, X-Scan will read target address from a text file. The file should contain a single address or range of address like the "IP address range" in each line.

    "Global options":
    
      "Modules" - Select the plug-ins what you want to use.
      "Parallel scanning" - Set the maximal number of parallel host and thread.
      "Network" - Select your network interface.
      "Report" - The final report file what located in the directory "log", support TXT, HTML and XML format currently.
      "Others":
        "Skip host when failed to get response" - If this checkbox is checked, target will be skiped with no response by "ICMP Ping" and "TCP Ping" before scanning.
        "Scan always" - Such as the caption.
        "Skip host when no open port has been found" - If X-Scan can't find any TCP port within the "Scan port", X-Scan will cancel the scan action.

    "Plug-in options":
      You can set the options of every plug-in in this module.


6. Frequently asked questions:

    Q: Does X-Scan work exactly without WinPCap?
    A: If the WinPCap driver hasn't been installed in your system, X-Scan will install WinPCap 3.1 beta4 automatically, otherwise X-Scan use the current version of WinPCap driver.

    Q: I can find 10 "checkhost.exe" in my task list when  I'm checking a subnet, why?
    A: X-Scan will create sub-process for every host. The sub-processes will terminate automatically after scanning. You can specify this number by parameter "-t".
    
    Q: Why did my computer rebooted when X-Scan was working?
    A: WinPcap does not work well if a firewall is installed on the same machine. You should disable or uninstall the firewall and try again.

    Q: Why did X-Scan identify target OS incorrectly?
    A: If target filtered NETBIOS and SNMP protocol and has strange TCP/IP stack fingerprinter, X-Scan can't identify it's OS correctly, you should judged by yourself.
    
    Q: Why did I selected the "SYN" method to scan TCP port but X-Scan used "TCP" method actually?
    A: Only under Windows 2000, SYN scan and the ability of identifing target OS passively are available, the permission of administrator is required simultaneously.

    Q: Dose the plug-ins of X-Scan 2.3 is compatible with X-Scan 3.0?
    A: No, X-Scan 3.0 changed the plug-in interface for the purpose of friends can develop plug-ins conveniently. So the old plug-ins need some modification.
    
    Q: How can I check the weak password with added password?
    A: Dictionary shipped with X-Scan is a simple demo. The better is used your own dictonary.

    Q: How can I install X-Scan to my system, and how can I register it?
    A: X-Scan which is absolutely free can be executed immediately after being decompressed without registration and installation (install WinPCap 3.1 beta4 automatically).


7. Release history:

    X-Scan v3.3     --  release date: 07/18/2005, optimized the main program and NASL library; fixed known BUGs in the previous v3.2; update NASL scripts.
    Thank quack, killer and coolc for their hard work in testing this version, and thank our enthusiastic friends again who have ever feedback with good suggestion.

    X-Scan v3.2     --  release date: 04/08/2005. Updated NASL library to nessus 2.2.4, optimized the main program and NASL library, added HTTP/TELNET/SSH/VNC/CVS/IMAP/NNTP weak password brute crack.
    Thank quack for providing so much good idea, and thank our enthusiastic friends again who have ever feedback with good suggestion.

    X-Scan v3.1     --  release date: 03/25/2004. Modified the "Active" plug-in, added "SNMP" and "NETBIOS" plug-ins, optimized the main program and NASL library.

    X-Scan v3.02    --  release date: 03/08/2004. There are some bugs in "WinPCap 3.1 beta", that maybe cause an exception in CheckHost.exe. So I replaced "WinPCap 3.1 beta" by "WinPCap 2.3", I recommended you to remove "WinPCap 3.1 beta" before you run X-Scan.

    X-Scan v3.0     --  release date: 03/01/2004. Fixed known BUGs in the previous v3.0 beta, optimized the main program and plug-ins; updated nasl.dll to support the latest nessus attack scripts; provided a simple library for the purpose of everyone can develop plug-in expediently.
    Thank wuxiu and quack for collected nessus attack scripts, thank san for the web page about X-Scan project, and thank our enthusiastic friends again who have ever feed back with good suggestion.

    X-Scan v3.0(beta) -- release date: 12/30/2003. Updated main program, added the NASL-plug-in to load all the nessus attack scripts; modified the plug-in interface for the purpose of developping plug-in expediently; enhanced the "identify remote OS" function; threw away some plug-ins what completed by NASL scripts.
    Thank isno and Enfis for their excellent plug-ins; thank wuxiu and quack for collected nessus attack scripts; thank our enthusiastic friends who have feed back with good suggestion.

    X-Scan v2.3     -- release date: 09/29/2002. Added the SSL-plug-in to check SSL vulnerability; updated PORT/HTTP/IIS-plug-in; updated GUI and changed it's style.
    Thank ilsy for excellent plug-ins.

    X-Scan v2.2     -- release date: 09/12/2002. Changed the style of result index file; enlarged RPC vulnerability database; fixed known BUGs in the previous v2.1.
    Thank xundi, quack and stardust for neaten vulnerability database.

    X-Scan v2.1     -- release date: 09/08/2002. Allowed scanning specific SNMP-Info-plug-in options; Link "vulnerability description" of HTTP-plug-in, IIS-plug-in and RPC-plug-in to "xfocus" vulnerability search engine; fixed all the known BUGs in the previous v2.0.

    X-Scan v2.0     -- release date: 08/07/2002. Added the TraceRoute-plug-in, SNMP-Info-plug-in; updated NETBIOS-plug-in, added remote register information scan; updated IIS-plug-in, added .ASP vulnerabities scan; modified part of plug-in interface; updated graphical interfaces, added "update online" function; enlarged CGI vulnerability database; fixed all the known BUGs in the previous v1.3.
    Thank precious information or excellent plug-in provided by quack, stardust, sinister, ilsy, bingle, santa, and many thanks to our enthusiastic friends who have ever feed back with good suggestion.

    X-Scan v1.3     -- release date: 12/11/2001. Modifed the OS-detection bug in PORT-plug-in.

    X-Scan v1.2     -- release date: 12/02/2001. Updated HTTP-plug-in and IIS-plug-in, added the detection of error pages which are redirected; updated PORT-plug-in, check port status by standard TCP connect() when fail to create Raw-Socket.

    X-Scan v1.1     -- release date: 11/25/2001. Transfered all scanning functions to plug-ins, and turn main program to contain; updated graphical interface program; modified multithreading mode, made plug-ins share threads and increase scanning speed; added SMTP, POP3 weak password scanning; added IIS UTF-Code vulnerabilities exploit; expanded CGI vulnerabilities list.
    My thanks to xundi, quack, casper, wollf and Huang Cheng for providing so much valuable information. A special thanks to xundi and quack for their hard work in testing this version.

    X-Scan v1.0(beta) -- release date: 07/12/2001. Added the detection of remote OS type and version based on TCP/IP stack fingerprinter; added the function of searching the geographical location of remote host; added the scanning of IIS ".ida/.idq" vulnerabilities in "-iis" option, and updated the description of this vulnerability; allowed scanning specific port scope (by modifying "[PORT-LIST]\port=" in "dat\config.ini"); allowed user using "%" to replace all user names when editing password dictionary in "-ntpass"; updated CGI vulnerabilities list,and clarified CGI vulnerabilities to increase the scanning speed.
    My thanks to cloud and Feng Zhihong for providing their great software. And thank you once again, quack, for your encouragement, faith, and support over the past years.

    X-Scanner v0.61 --  release date: 05/17/2001. Added the exploit of Microsoft IIS CGI Filename Decode Error Vulnerability in "-iis" option.

    X-Scanner v0.6  --  release date: 05/15/2001. Add "-iis" option, being used for scanning "unicode" & "remote .printer overflow" vulnerability of IIS server; updated the description of vulnerabilities; adjusted the timeouts, avoided "scan unfinished" caused by timeout; upload warning text to "C:\" instead of changing homepage automatically.

    X-Scanner v0.5  --  release date: 04/30/2001. Modified command line parameter, and made it more understandble; enlarged CGI vulnerability database; expanded the NT weak password scanning function.
    Thank santa and colossus for excellent plug-ins.

    X-Scanner v0.42b --  release date: 03/07/2001. Modify the bug in "-b" option.

    X-Scanner v0.42 --  release date: 03/02/2001. Allowed user extend SQL-SERVER account.

    X-Scanner v0.41 --  release date: 02/19/2001. Modified the scanning-weak-password bug in former versions; optimized the script, and combined xscan.exe and xscan98.

    X-Scanner v0.4  --  release date: 02/15/2001. Added the scan for SQL-SERVER default account "sa"; made a simple GUI temporarily (all work can be done by one mouse!)

    X-Scanner v0.31 --  release date: 01/17/2001. Adjusted the port scan way and the format of export files; enhanced the Unicode decode vulnerability; provided a simple CGI list maintenance tool for win98.

    X-Scanner v0.3  --  release date: 12/27/2000. Added the thread timeout limitation; added proxy; enlarge CGI vulnerability database, added the scan for vulnerabilities such as Unicode decoding; Modified the memory leak bug. Internal test version.

    X-Scanner v0.2  --  release date: 12/12/2000. Internal test version.


8. Appendix:

    X-Scan is a totally free software. Any suggestions and feedbacks will be highly appreciated. I welcome email from any user with comments or bug fixes.
    Many thanks to the support of the members of xfocus, uid0 and ex-DarkSun. I can do nothing without you.
        
        -- glacier_at_xfocus.org

_____________________________________________________________
Question, advice, bug ... please mail to: xscan_at_xfocus.org
Copyright (C) http://www.xfocus.org
