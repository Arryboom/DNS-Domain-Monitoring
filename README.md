# DNS-Domain-Monitoring
Real-time DNS request monitoring for malicious domains and tunneling.

Mission Statement: Detect dns requests for malicious domains.  These requests could be tunneling or domains used in malware to pull additional files or callback through some other protocol.

Detect:
    What:
        - Known domain blacklists/whitelists (malware.com)
        - Domains matching DGA (asdf8783fasdf784jaf392.com)
        - Domain registration dates (Domains registered within last 30/60/x days
        - History within the organization (Google.com vs NeverSeenBefore.com)  


    How:
        - Weigh tests based on efficiency such that longer tests are ran last since DNS requests are extremely high volume
        - Sniff DNS requests at either DNS server on server at edge of network that is using a TAP to feed it network traffic.
  
Prevent:
    What:
        - Send spoofed DNS reply with NXDomain to requester before the true response can be returned.
