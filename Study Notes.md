# OSCP Study Notes

## The Penetration Testing Lifecycle

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

##### Passive Information Gathering

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

##### Active Information Gathering

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
   
   3. 
