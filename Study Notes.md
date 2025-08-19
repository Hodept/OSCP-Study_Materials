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
         
         1. 
            
            
