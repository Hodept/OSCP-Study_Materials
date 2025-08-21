# OSCP Study Notes

---------------------------

### The Penetration Testing Lifecycle

##### Lifecycle phases:

A typical penetration test comprises the following stages:

- Defining the Scope
- Information Gathering
- Vulnerability Detection
- Initial Foothold
- Privilege Escalation
- Lateral Movement
- Reporting/Analysis

Lessons Learned/Remediation

#### Passive Information Gathering

1. Passive Information Gathering, also known as [*Open-source
   Intelligence*](https://osintframework.com/) (OSINT), is the process of collecting openly-available information about a target, generally without any direct interaction with that target, in order to keep our footprint low.
   
   1. Example Passive tools
      
      1. Whois
      
      2. Google Hacking / LinkedIn searching etc.
         
         1. www.Dorksearch.com 
         
         2. `site:megacorpone.com`
         
         3. `site:megacorpone.com filetype:txt`
      
      3. NetCraft
         
         1. Detailed information about the site you are targeting. 
      
      4. Open-Source Code Repos
         
         1. Github / Github GIST
            
            1. Opensource tools that will search for usernames and passwords
               
               1. Gitrob
               
               2. Gitleaks
         
         2. GitLab
         
         3. SourceForge
      
      5. Shodan
         
         1. must have a free account to be able to use features here. 
      
      6. Security Headers
         
         1. https://securityheaders.com/
      
      7. Another scanning tool we can use is the *SSL Server Test* from [*Qualys SSL Labs*](https://www.ssllabs.com/ssltest/). This tool analyzes a server's SSL/TLS configuration and compares it against current best practices.

##### LLM-Powered Passive Information Gathering

* LLMs are particularly useful for this stage of pentesting because it
  deals largely with text, and LLMs—being trained on and specialized in
  processing text—are uniquely suited to extract valuable information
  from it.

* ChatGPT
  
  * ChatGPT does not perform live lookups by default,
    but it may simulate results from services like
    Netcraft, [*Datanyze*](https://www.datanyze.com/) and [*6sense*](https://6sense.com/company/mega-corp-one/5ba6667c7c866613751401d1?utm_source=chatgpt.com) based on its training data.
  
  * Example queries:
  
  * ```
    can you provide the best 20 google dorks for megacorpone.com website tailored for a penetration test?
    
    Retrieve the technology stack of the megacorpone.com website
    
    Can you print out all the public information about company structure and employees of megacorpone?
    ```

#### Active Information Gathering

1. [*Living Off the Land Binaries andScripts*](https://lolbas-project.github.io/) (LOLBAS) Or [Living Off the Land Binaries](https://www.hhs.gov/sites/default/files/living-off-land-attacks-tlpclear.pdf) (LOLBins)

###### DNS Enumeration

 Each domain can use different types of DNS records. Some of the most
common types of DNS records include:

- **NS**: Nameserver records contain the name of the authoritative
  servers hosting the DNS records for a domain.
- **A**: Also known as a host record, the "*a record*" contains the IPv4
  address of a hostname (such as www.megacorpone.com).
- **AAAA**: Also known as a quad A host record, the "*aaaa record*"
  contains the IPv6 address of a hostname (such as www.megacorpone.com).
- **MX**: Mail Exchange records contain the names of the servers
  responsible for handling email for the domain. A domain can contain
  multiple MX records.
- **PTR**: Pointer Records are used in reverse lookup zones and can
  find the records associated with an IP address.
- **CNAME**: Canonical Name Records are used to create aliases for
  other host records.
- **TXT**: Text records can contain any arbitrary data and be used
  for various purposes, such as domain ownership verification.

`HOST` is a cmdline tool that can be used to query DNS entries. 

1. Automated tools that might perform some sort of DNS enumeration as well. 
   
   1. DNSRecon
      
      1. Further information can be found via the man page for this tool. 
   
   2. DNSenum
      
      1. Further information can be found via the man page for this tool.

2. LOLBAS type tools. 
   
   1. `nslookup`
   
   2. `nslookup -type=TXT info.megacorptwo.com 192.168.50.151`
      
      1. In this example, we are specifically querying the 192.168.50.151 DNS
         server for any TXT record related to the **info.megacorptwo.com** host.

###### TCP/UDP Port Scanning

* Netcat 
  
  * `nc -nvv -w 1 -z 192.168.50.152 3388-3390`
  
  * Special Note about UDP
    
    * Most UDP scanners tend to use the standard "ICMP port unreachable"
      message to infer the status of a target port. However, this method can
      be completely unreliable when the target port is filtered by a
      firewall. In fact, in these cases, the scanner will report the target
      port as open because of the absence of the ICMP message.

* NMAP
  
  * Our results imply that a full Nmap scan of a class C network (254
    hosts) would result in sending over *1000 MB* of traffic to the network.
    Ideally, a full TCP and UDP port scan of every single target machine
    would provide the most accurate information about exposed network
    services. However, we clearly need to balance any traffic restrictions
    (such as a slow uplink) with discovering additional open ports and
    services via a more exhaustive scan. This is especially true for
    larger networks, such as a class A or B network assessment.
    
    * Scripts for Nmap can be found in `/usr/share/nmap/scripts`

* RustScan

* Masscan

* Windows has built in scanner of "Test-NetConnection" inside of powershell
  
  * ```powershell
    1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
    ```

###### SMB Enumeration

* The [*NetBIOS*](https://www.techtarget.com/searchnetworking/definition/NetBIOS) service listens on TCP port 139, as well as several UDP ports. It should be noted that SMB (TCP port 445) and NetBIOS are two separate protocols. NetBIOS is an independent session layer protocol and service that allows computers on a local network to communicate with each other. While modern implementations of SMB can work without NetBIOS, [*NetBIOS over TCP*](https://www.pcmag.com/encyclopedia/term/netbios-over-tcpip) (NBT) is required for backward compatibility and these are often enabled together. This also means the enumeration of these two services often goes together.
  
  * `nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254`

* nbtscan can be used to uniquely identify SMB hosts. 
  
  * `sudo nbtscan -r 192.168.50.0/24`

* Windows has the ability to perform some netbios and SMB enumeration by default. 
  
  * `net view \\dc01 /all`
    
    * By providing the `/all` keyword, we can list the administrative shares
      ending with the dollar sign.

###### SMTP Enumeration

* The [*Simple Mail Transport Protocol*](https://www.pcmag.com/encyclopedia/term/smtp) (SMTP) supports several interesting commands, such as *VRFY* and *EXPN*. A VRFY request asks the server to verify an email address, while EXPN asks the server for the membership of a mailing list. These can often
  be abused to verify existing users on a mail server, which is useful information during a penetration test.
  
  * Enumeration can be performed by multiple sets of tools
    
    * nc `nc -nv 192.168.50.8 25`
    
    * python scripting
    
    * windows Test-NetConnection `Test-NetConnection -Port 25 192.168.50.8`
    
    * `dism /online /Enable-Feature /FeatureName:TelnetClient`
    
    * `telnet 192.168.50.8 25`

###### SNMP Enumeration

*SNMP MIB Tree*.

The SNMP *Management Information Base* (MIB) is a database containing
information typically related to network management. The database is
organized like a tree, with branches that represent different
organizations or network functions. The leaves of the tree (or final
endpoints) correspond to specific variable values that can then be
accessed and probed by an external user. The [*IBM Knowledge
Center*](https://www.ibm.com/support/knowledgecenter/ssw_aix_71/commprogramming/mib.html) contains a wealth of information about the MIB tree.

| OID Value              | Information Therein |
| ---------------------- | ------------------- |
| 1.3.6.1.2.1.25.1.6.0   | System Processes    |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs    |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path      |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units       |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name       |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts       |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports     |

```bash
kali@kali:~$ snmpwalk -c public -v1 -t 10 192.168.50.151
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.3
iso.3.6.1.2.1.1.3.0 = Timeticks: (78235) 0:13:02.35
iso.3.6.1.2.1.1.4.0 = STRING: "admin@megacorptwo.com"
iso.3.6.1.2.1.1.5.0 = STRING: "dc01.megacorptwo.com"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 79
iso.3.6.1.2.1.2.1.0 = INTEGER: 24
```

```bash
#Targeting the User Accounts
kali@kali:~$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.107.114.98.116.103.116 = STRING: "krbtgt"
iso.3.6.1.4.1.77.1.2.25.1.1.7.115.116.117.100.101.110.116 = STRING: "student"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"

```

```bash
#targeting Processes
kali@kali:~$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
iso.3.6.1.2.1.25.4.2.1.2.88 = STRING: "Registry"
iso.3.6.1.2.1.25.4.2.1.2.260 = STRING: "smss.exe"
iso.3.6.1.2.1.25.4.2.1.2.316 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.372 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.472 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.476 = STRING: "wininit.exe"
iso.3.6.1.2.1.25.4.2.1.2.484 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.540 = STRING: "winlogon.exe"
iso.3.6.1.2.1.25.4.2.1.2.616 = STRING: "services.exe"
iso.3.6.1.2.1.25.4.2.1.2.632 = STRING: "lsass.exe"
iso.3.6.1.2.1.25.4.2.1.2.680 = STRING: "svchost.exe"
...
```

Another SNMP enumeration technique is to list all the current TCP listening ports:

```bash
kali@kali:~$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.88.0.0.0.0.0 = INTEGER: 88
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.135.0.0.0.0.0 = INTEGER: 135
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.389.0.0.0.0.0 = INTEGER: 389
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.445.0.0.0.0.0 = INTEGER: 445
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.464.0.0.0.0.0 = INTEGER: 464
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.593.0.0.0.0.0 = INTEGER: 593
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.636.0.0.0.0.0 = INTEGER: 636
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3268.0.0.0.0.0 = INTEGER: 3268
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3269.0.0.0.0.0 = INTEGER: 3269
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5357.0.0.0.0.0 = INTEGER: 5357
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5985.0.0.0.0.0 = INTEGER: 5985
```

###### Active LLM-Aided Enumeration

We can use the LLM to target a site and prompt it accordingly.   

```bash
Using public data from MegacorpOne's website and any information that can be inferred about its organizational structure, products, or services, generate a comprehensive list of potential subdomain names.
	•	Incorporate common patterns used for subdomains, such as:
	•	Infrastructure-related terms (e.g., "api", "dev", "test", "staging").
	•	Service-specific terms (e.g., "mail", "auth", "cdn", "status").
	•	Departmental or functional terms (e.g., "hr", "sales", "support").
	•	Regional or country-specific terms (e.g., "us", "eu", "asia").
	•	Factor in industry norms and frequently used terms relevant to MegacorpOne's sector.

Finally, compile the generated terms into a structured wordlist of 1000  words, optimized for subdomain brute-forcing against megacorpone.com

Ensure the output is in a clean, lowercase format with no duplicates, no bulletpoints and ready to be copied and pasted.
Make sure the list contains 1000 unique entries.
```

* gobuster can be used to brutforce possible DNS names for a domain.  It has a DNS option and will leverage any wordlist that we might include as well. 
  
  * `gobuster dns -d megacorpone.com -w wordlist.txt -t 10`

-------------------------------

### Vuln Scanning Theory

#### How Vulnerability Scanners Work

* The basic process of an automated vulnerability scanner can be described as:
  
  1. Host discovery
  2. Port scanning
  3. Operating system, service, and version detection
  4. Matching the results to a vulnerability database

* A manual vulnerability scan will inevitably be very resource-intensive
  and time-consuming. When there is a huge amount of data to analyze, we
  often reach our cognitive limit quickly and overlook vital details. On
  the other hand, manual vulnerability scanning allows for the discovery
  of complex and logical vulnerabilities that are rather difficult to
  discover using any type of automated scanner.

* Automated vulnerability scans are invaluable when working on
  engagements for a multitude of reasons. First, in nearly all types
  of assessments, we have time constraints. Therefore, when we have
  a big enterprise network to scan, we cannot manually review every
  system. This is especially true when thinking about new or complex
  vulnerabilities. Second, by using automated scanners, we can quickly
  identify easily detected vulnerabilities and other low-hanging fruit.

##### Types of Vuln Scans

The location where we perform the vulnerability scan determines the target visibility.

1. Internal scan

2. External scan

3. authenticated scan

4. unauthenticated scan

##### Considerations when Scanning

In large engagements, we need to configure the vulnerability scanner carefully to get meaningful and relevant results.

1. Duration of the scan

2. Target Visibility

3. Rate Limiting technologies

4. Parallel Scanning and Network Bandwidth

#### Scanning with Nessus

1. Nessus provides templates that are grouped into the three categories *Discovery*, *Vulnerabilities*, and *Compliance*.
   
   1. The *Compliance* category is only available in the enterprise
      version as well as the *Mobile Device Scan* template. The
      only template in the *Discovery* category is *Host Discovery*,
      which can be used to create a list of live hosts and their open
      ports. 
   
   2. The *Vulnerabilities* category consists of templates for
      critical vulnerabilities or vulnerability groups e.g. [*PrintNightmare*](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) or [*Zerologon*](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472) as well as templates for common scanning areas e.g. *Web Application
      Tests* or *Malware Scans*.

2. Nessus also provides three general vulnerability scanning templates:
   
   1. The *Basic Network Scan* performs a full scan with the majority of
      settings predefined. It will detect a broad variety of vulnerabilities
      and is therefore the recommended scanning template by Nessus. We also
      have the option to customize these settings and recommendations.
   
   2. The *Advanced Scan* is a template without any predefined settings.
      We can use this when we want to fully customize our vulnerability scan
      or if we have specific needs.
   
   3. The last general scanning template, *Advanced Dynamic Scan*,
      also comes without any predefined settings or recommendations.

3. Authenticated scans
   
   1. While we can also use SSH on Windows, in most cases, we will use [*Server Message Block*](https://en.wikipedia.org/wiki/Server_Message_Block) (SMB) and [*Windows Management Instrumentation*](https://en.wikipedia.org/wiki/Windows_Management_Instrumentation) (WMI) to perform authenticated vulnerability scans against Windows targets. Both methods allow us to use local or domain accounts and different authentication options.
   
   2. Due to the nature of UAC, it can also interfere with our scan. [We can configure UAC to allow Nessus or temporarily disable it](https://docs.tenable.com/nessus/Content/EnableWindowsLoginsForLocalAndRemoteAudits.htm). We should consult the [*Tenable Documentation*](https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm), especially for Windows targets before we start our first authenticated scan.

##### Nessus Plugins

1. By default, Nessus will enable several plugins behind the scenes when running a default template. While this is certainly useful in many scenarios, we can also fine-tune our options to quickly run a single plugin. We can use this feature to validate a previous finding or to quickly discover all the targets in an environment that are at risk of a specific vulnerability.

#### Vuln Scanning with NMAP

##### NSE Vulnerability Scripts

* As an alternative to Nessus, we can also use the [NSE](https://nmap.org/book/man-nse.html) to perform automated
  vulnerability scans. NSE scripts extend the basic functionality of
  Nmap to do a variety of networking tasks. These tasks are grouped
  into categories around cases such as vulnerability detection, brute
  forcing, and network discovery. The scripts can also extend the
  version detection and information-gathering capabilities of Nmap

* Some of the standard NSE scripts are quite outdated. Fortunately, the [*vulners*](https://nmap.org/nsedoc/scripts/vulners.html) script was integrated, which provides current vulnerability information about detected service versions from the [*Vulners Vulnerability Database*](https://vulners.com). The script itself has the categories *safe*, *vuln*, and *external*.
  
  * The vulners script not only shows us information about the CVEs found
    but also the CVSS scores and links for additional information.
  
  * Another useful feature of the vulners script is that it also lists *Proof of Concepts* for the found vulnerabilities, which are marked with "*EXPLOIT*". However, without a successful service detection, the vulners script will not provide any results.

##### Working with NSE Scripts

* Sometimes want to check for a specific CVE. This is especially helpful when we want to scan a network for the existence of a vulnerability. If we do this with the vulners script, we will need to review an enormous amount of information. For most  modern vulnerabilities, we need to integrate dedicated NSE scripts manually.
  
  * Google the CVE and a NSE script. 
    
    * GitHub has examples listed there.
  
  * Download and copy the script into the scripting folder for NMAP
    
    * `sudo cp /home/kali/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse`
  
  * Update the script DB. 
    
    * `sudo nmap --script-updatedb`
  
  * Initiate the scan. 
    
    * `sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124`

* Use Nmap when there isn't a full-fledged vulnerability scanner available or when we want to verify findings from other tools.

---------------------------------------

### Introduction to Web Application Attacks
