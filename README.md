# A remote Nagios check for SSL/TLS certificates

This is a remote nagios check written in php to check SSL/TLS certificates

* Checks entire certificate chain for valid dates
* Offers performance data
* Sane defaults for warning and critical levels

##Compatibility
* Tested on Debian 7 and 8.

##Requirements
* php
* openssl

##Defaults
Warning defaults to 30 days before any certificate in the chain expires 
Critical defaults to any certificate in the chain being invalid

##Usage
    Usage:
        check_ssl_cert -H <Host> [-p <port>] [-w <SecondsTillWarn>] [-c <SecondsTillCritical>]
  
    This script will check an SSL/TLS connection to verify the validity of the
    certificates used in the connection. If any certificates in the certificate
    chain are invalid then the script will return an error. If any certificate is
    nearing its expiration date then a warning will be issued.
    
    Note: If ports 21, 25, 110, or 143 is specified then starttls is assumed.
