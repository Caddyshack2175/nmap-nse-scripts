local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs a testssl.sh test on SSL/TLS port and displays tool output.
]]

---
-- Script runs on ssl ports only, the default script checks for Server Default settings and Vulnerbility checks
-- Script requirments are that testssl.sh is installed to the following directory: 
-- * /usr/bin/testssl
-- 
-- $ nmap -sT --script=testssl.nse -p 80,443 www.google.com
-- Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-11 10:12 BST
-- Nmap scan report for www.google.com (216.58.201.100)
-- Host is up (0.014s latency).
-- Other addresses for www.google.com (not scanned): 2a00:1450:4009:821::2004
-- rDNS record for 216.58.201.100: prg03s02-in-f4.1e100.net
-- 
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- 443/tcp open  https
-- | testssl: 
-- |   
-- |   No engine or GOST support via engine with your /usr/bin/openssl
-- |   
-- |   ###########################################################
-- |       testssl       3.0.7 from https://testssl.sh/
-- |   
-- |         This program is free software. Distribution and
-- |                modification under GPLv2 permitted.
-- |         USAGE w/o ANY WARRANTY. USE IT AT YOUR OWN RISK!
-- |   
-- |          Please file bugs @ https://testssl.sh/bugs/
-- |   
-- |   ###########################################################
-- |   
-- |    Using "OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)" [~76 ciphers]
-- |    on test:/usr/bin/openssl
-- |    (built: "Feb  5 13:19:41 2025", platform: "debian-amd64")
-- |   
-- |   
-- |    Start 2025-04-11 10:12:53        -->> 216.58.201.100:443 (www.google.com) <<--
-- |   
-- |    Further IP addresses:   2a00:1450:4009:821::2004 
-- |    rDNS (216.58.201.100):  lhr48s48-in-f4.1e100.net. prg03s02-in-f4.1e100.net. prg03s02-in-f100.1e100.net.
-- |    Service detected:       HTTP
-- |   
-- |   
-- |    Testing server defaults (Server Hello) 
-- |   
-- |    TLS extensions (standard)    "renegotiation info/#65281" "EC point formats/#11" "session ticket/#35" "next protocol/#13172" "key share/#51" "supported versions/#43" "extended master secret/#23"
-- |                                 "application layer protocol negotiation/#16"
-- |    Session Ticket RFC 5077 hint 100800 seconds but: PFS requires session ticket keys to be rotated < daily !
-- |    SSL Session ID support       no
-- |    Session Resumption           Tickets: yes, ID: no
-- |    TLS clock skew               0 sec from localtime
-- |   
-- |     Server Certificate #1
-- |      Signature Algorithm          SHA256 with RSA
-- |      Server key size              RSA 2048 bits
-- |      Server key usage             Digital Signature, Key Encipherment
-- |      Server extended key usage    TLS Web Server Authentication
-- |      Serial                       BC1DD3C0ABE066330AFEF9B6E200F42E (OK: length 16)
-- |      Fingerprints                 SHA1 sha1 90D1B43C013213E0106B238037C17DC6E604DC5F
-- |                                   SHA256 sha256 CF5E91A7CEB8B27E9588CCC0510B9E91089D2D1260562ACAA36E16EF13E300C4
-- |      Common Name (CN)             www.google.com 
-- |      subjectAltName (SAN)         www.google.com 
-- |      Issuer                       WR2 (Google Trust Services from US)
-- |      Trust (hostname)             Ok via SAN (same w/o SNI)
-- |      Chain of trust               Ok   
-- |      EV cert (experimental)       no 
-- |      ETS/"eTLS", visibility info  not present
-- |      Certificate Validity (UTC)   62 >= 60 days (2025-03-20 11:20 --> 2025-06-12 11:20)
-- |      # of certificates provided   3
-- |      Certificate Revocation List  --
-- |      OCSP URI                     http://o.pki.goog/wr2
-- |      OCSP stapling                not offered
-- |      OCSP must staple extension   --
-- |      DNS CAA RR (experimental)    available - please check for match with "Issuer" above: issue=pki.goog
-- |      Certificate Transparency     yes (certificate extension)
-- |   
-- |     Server Certificate #2
-- |      Signature Algorithm          SHA256 with RSA
-- |      Server key size              EC 256 bits
-- |      Server key usage             Digital Signature
-- |      Server extended key usage    TLS Web Server Authentication
-- |      Serial                       B9329CBDA9EF7F4412098E722A6845D3 (OK: length 16)
-- |      Fingerprints                 SHA1 sha1 405C8199DA0136FEE4602B67513DC2628D9A3847
-- |                                   SHA256 sha256 AD9DB417DFC047407D911984E4B13769038070BC511868A22C4F70BE92E7A9BD
-- |      Common Name (CN)             www.google.com 
-- |      subjectAltName (SAN)         www.google.com 
-- |      Issuer                       WR2 (Google Trust Services from US)
-- |      Trust (hostname)             Ok via SAN (same w/o SNI)
-- |      Chain of trust               Ok   
-- |      EV cert (experimental)       no 
-- |      ETS/"eTLS", visibility info  not present
-- |      Certificate Validity (UTC)   62 >= 60 days (2025-03-20 11:20 --> 2025-06-12 11:20)
-- |      # of certificates provided   3
-- |      Certificate Revocation List  --
-- |      OCSP URI                     http://o.pki.goog/wr2
-- |      OCSP stapling                not offered
-- |      OCSP must staple extension   --
-- |      DNS CAA RR (experimental)    available - please check for match with "Issuer" above: issue=pki.goog
-- |      Certificate Transparency     yes (certificate extension)
-- |   
-- |   
-- |    Testing vulnerabilities 
-- |   
-- |    Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
-- |    CCS (CVE-2014-0224)                       not vulnerable (OK)
-- |    Ticketbleed (CVE-2016-9244), experiment.  not vulnerable (OK)
-- |    ROBOT                                     not vulnerable (OK)
-- |    Secure Renegotiation (RFC 5746)           supported (OK)
-- |    Secure Client-Initiated Renegotiation     not vulnerable (OK)
-- |    CRIME, TLS (CVE-2012-4929)                not vulnerable (OK)
-- |    BREACH (CVE-2013-3587)                    potentially NOT ok, "gzip" HTTP compression detected. - only supplied "/" tested
-- |                                              Can be ignored for static pages or if no secrets in the page
-- |    POODLE, SSL (CVE-2014-3566)               not vulnerable (OK)
-- |    TLS_FALLBACK_SCSV (RFC 7507)              No fallback possible (OK), no protocol below TLS 1.2 offered
-- |    SWEET32 (CVE-2016-2183, CVE-2016-6329)    VULNERABLE, uses 64 bit block ciphers
-- |    FREAK (CVE-2015-0204)                     not vulnerable (OK)
-- |    DROWN (CVE-2016-0800, CVE-2016-0703)      not vulnerable on this host and port (OK)
-- |                                              make sure you don't use this certificate elsewhere with SSLv2 enabled services
-- |                                              https://censys.io/ipv4?q=sha256 CF5E91A7CEB8B27E9588CCC0510B9E91089D2D1260562ACAA36E16EF13E300C4 could help you to find out
-- |    LOGJAM (CVE-2015-4000), experimental      not vulnerable (OK): no DH EXPORT ciphers, no DH key detected with <= TLS 1.2
-- |    BEAST (CVE-2011-3389)                     not vulnerable (OK), no SSL3 or TLS1
-- |    LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS. Check patches
-- |    RC4 (CVE-2013-2566, CVE-2015-2808)        no RC4 ciphers detected (OK)
-- |   
-- |   
-- |    Done 2025-04-11 10:13:37 [  48s] -->> 216.58.201.100:443 (www.google.com) <<--
-- |   
-- |_  
-- 
-- Nmap done: 1 IP address (1 host up) scanned in 47.76 seconds
-- 
-- Below shows the script options with ciphers
-- 
-- $ nmap -sT --script=testssl.nse --script-args=testssl.ciphers -p 443 www.google.com
-- Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-11 10:03 BST
-- Nmap scan report for www.google.com (142.250.178.4)
-- Host is up (0.014s latency).
-- Other addresses for www.google.com (not scanned): 2a00:1450:4009:821::2004
-- rDNS record for 142.250.178.4: lhr48s27-in-f4.1e100.net
-- 
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | testssl: 
-- |   
-- |   No engine or GOST support via engine with your /usr/bin/openssl
-- |   
-- |   ###########################################################
-- |       testssl       3.0.7 from https://testssl.sh/
-- |   
-- |         This program is free software. Distribution and
-- |                modification under GPLv2 permitted.
-- |         USAGE w/o ANY WARRANTY. USE IT AT YOUR OWN RISK!
-- |   
-- |          Please file bugs @ https://testssl.sh/bugs/
-- |   
-- |   ###########################################################
-- |   
-- |    Using "OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)" [~76 ciphers]
-- |    on test:/usr/bin/openssl
-- |    (built: "Feb  5 13:19:41 2025", platform: "debian-amd64")
-- |   
-- |   
-- |    Start 2025-04-11 10:03:43        -->> 142.250.178.4:443 (www.google.com) <<--
-- |   
-- |    Further IP addresses:   2a00:1450:4009:821::2004 
-- |    rDNS (142.250.178.4):   lhr48s27-in-f4.1e100.net.
-- |    Service detected:       HTTP
-- |   
-- |   
-- |    Testing server defaults (Server Hello) 
-- |   
-- |    TLS extensions (standard)    "renegotiation info/#65281" "EC point formats/#11" "session ticket/#35" "next protocol/#13172" "key share/#51" "supported versions/#43" "extended master secret/#23"
-- |                                 "application layer protocol negotiation/#16"
-- |    Session Ticket RFC 5077 hint 100800 seconds but: PFS requires session ticket keys to be rotated < daily !
-- |    SSL Session ID support       no
-- |    Session Resumption           Tickets: yes, ID: no
-- |    TLS clock skew               0 sec from localtime
-- |   
-- |     Server Certificate #1
-- |      Signature Algorithm          SHA256 with RSA
-- |      Server key size              RSA 2048 bits
-- |      Server key usage             Digital Signature, Key Encipherment
-- |      Server extended key usage    TLS Web Server Authentication
-- |      Serial                       BC1DD3C0ABE066330AFEF9B6E200F42E (OK: length 16)
-- |      Fingerprints                 SHA1 sha1 90D1B43C013213E0106B238037C17DC6E604DC5F
-- |                                   SHA256 sha256 CF5E91A7CEB8B27E9588CCC0510B9E91089D2D1260562ACAA36E16EF13E300C4
-- |      Common Name (CN)             www.google.com 
-- |      subjectAltName (SAN)         www.google.com 
-- |      Issuer                       WR2 (Google Trust Services from US)
-- |      Trust (hostname)             Ok via SAN (same w/o SNI)
-- |      Chain of trust               Ok   
-- |      EV cert (experimental)       no 
-- |      ETS/"eTLS", visibility info  not present
-- |      Certificate Validity (UTC)   62 >= 60 days (2025-03-20 11:20 --> 2025-06-12 11:20)
-- |      # of certificates provided   3
-- |      Certificate Revocation List  --
-- |      OCSP URI                     http://o.pki.goog/wr2
-- |      OCSP stapling                not offered
-- |      OCSP must staple extension   --
-- |      DNS CAA RR (experimental)    available - please check for match with "Issuer" above: issue=pki.goog
-- |      Certificate Transparency     yes (certificate extension)
-- |   
-- |     Server Certificate #2
-- |      Signature Algorithm          SHA256 with RSA
-- |      Server key size              EC 256 bits
-- |      Server key usage             Digital Signature
-- |      Server extended key usage    TLS Web Server Authentication
-- |      Serial                       B9329CBDA9EF7F4412098E722A6845D3 (OK: length 16)
-- |      Fingerprints                 SHA1 sha1 405C8199DA0136FEE4602B67513DC2628D9A3847
-- |                                   SHA256 sha256 AD9DB417DFC047407D911984E4B13769038070BC511868A22C4F70BE92E7A9BD
-- |      Common Name (CN)             www.google.com 
-- |      subjectAltName (SAN)         www.google.com 
-- |      Issuer                       WR2 (Google Trust Services from US)
-- |      Trust (hostname)             Ok via SAN (same w/o SNI)
-- |      Chain of trust               Ok   
-- |      EV cert (experimental)       no 
-- |      ETS/"eTLS", visibility info  not present
-- |      Certificate Validity (UTC)   62 >= 60 days (2025-03-20 11:20 --> 2025-06-12 11:20)
-- |      # of certificates provided   3
-- |      Certificate Revocation List  --
-- |      OCSP URI                     http://o.pki.goog/wr2
-- |      OCSP stapling                not offered
-- |      OCSP must staple extension   --
-- |      DNS CAA RR (experimental)    available - please check for match with "Issuer" above: issue=pki.goog
-- |      Certificate Transparency     yes (certificate extension)
-- |   
-- |   
-- |    Testing vulnerabilities 
-- |   
-- |    Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
-- |    CCS (CVE-2014-0224)                       not vulnerable (OK)
-- |    Ticketbleed (CVE-2016-9244), experiment.  not vulnerable (OK)
-- |    ROBOT                                     not vulnerable (OK)
-- |    Secure Renegotiation (RFC 5746)           supported (OK)
-- |    Secure Client-Initiated Renegotiation     not vulnerable (OK)
-- |    CRIME, TLS (CVE-2012-4929)                not vulnerable (OK)
-- |    BREACH (CVE-2013-3587)                    potentially NOT ok, "gzip" HTTP compression detected. - only supplied "/" tested
-- |                                              Can be ignored for static pages or if no secrets in the page
-- |    POODLE, SSL (CVE-2014-3566)               not vulnerable (OK)
-- |    TLS_FALLBACK_SCSV (RFC 7507)              No fallback possible (OK), no protocol below TLS 1.2 offered
-- |    SWEET32 (CVE-2016-2183, CVE-2016-6329)    VULNERABLE, uses 64 bit block ciphers
-- |    FREAK (CVE-2015-0204)                     not vulnerable (OK)
-- |    DROWN (CVE-2016-0800, CVE-2016-0703)      not vulnerable on this host and port (OK)
-- |                                              make sure you don't use this certificate elsewhere with SSLv2 enabled services
-- |                                              https://censys.io/ipv4?q=sha256 CF5E91A7CEB8B27E9588CCC0510B9E91089D2D1260562ACAA36E16EF13E300C4 could help you to find out
-- |    LOGJAM (CVE-2015-4000), experimental      not vulnerable (OK): no DH EXPORT ciphers, no DH key detected with <= TLS 1.2
-- |    BEAST (CVE-2011-3389)                     not vulnerable (OK), no SSL3 or TLS1
-- |    LUCKY13 (CVE-2013-0169), experimental     potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS. Check patches
-- |    RC4 (CVE-2013-2566, CVE-2015-2808)        no RC4 ciphers detected (OK)
-- |   
-- |   
-- |    Testing ciphers per protocol via OpenSSL plus sockets against the server, ordered by encryption strength 
-- |   
-- |   Hexcode  Cipher Suite Name (OpenSSL)       KeyExch.   Encryption  Bits     Cipher Suite Name (IANA/RFC)
-- |   -----------------------------------------------------------------------------------------------------------------------------
-- |   SSLv2  
-- |   SSLv3  
-- |   TLS 1  
-- |    xc014   ECDHE-RSA-AES256-SHA              ECDH 253   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                 
-- |    xc00a   ECDHE-ECDSA-AES256-SHA            ECDH 253   AES         256      TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               
-- |    x35     AES256-SHA                        RSA        AES         256      TLS_RSA_WITH_AES_256_CBC_SHA                       
-- |    xc013   ECDHE-RSA-AES128-SHA              ECDH 253   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                 
-- |    xc009   ECDHE-ECDSA-AES128-SHA            ECDH 253   AES         128      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               
-- |    x2f     AES128-SHA                        RSA        AES         128      TLS_RSA_WITH_AES_128_CBC_SHA                       
-- |    x0a     DES-CBC3-SHA                      RSA        3DES        168      TLS_RSA_WITH_3DES_EDE_CBC_SHA                      
-- |   TLS 1.1  
-- |    xc014   ECDHE-RSA-AES256-SHA              ECDH 253   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                 
-- |    xc00a   ECDHE-ECDSA-AES256-SHA            ECDH 253   AES         256      TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               
-- |    x35     AES256-SHA                        RSA        AES         256      TLS_RSA_WITH_AES_256_CBC_SHA                       
-- |    xc013   ECDHE-RSA-AES128-SHA              ECDH 253   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                 
-- |    xc009   ECDHE-ECDSA-AES128-SHA            ECDH 253   AES         128      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               
-- |    x2f     AES128-SHA                        RSA        AES         128      TLS_RSA_WITH_AES_128_CBC_SHA                       
-- |    x0a     DES-CBC3-SHA                      RSA        3DES        168      TLS_RSA_WITH_3DES_EDE_CBC_SHA                      
-- |   TLS 1.2  
-- |    xc030   ECDHE-RSA-AES256-GCM-SHA384       ECDH 253   AESGCM      256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384              
-- |    xc02c   ECDHE-ECDSA-AES256-GCM-SHA384     ECDH 253   AESGCM      256      TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384            
-- |    xc014   ECDHE-RSA-AES256-SHA              ECDH 253   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                 
-- |    xc00a   ECDHE-ECDSA-AES256-SHA            ECDH 253   AES         256      TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               
-- |    xcca9   ECDHE-ECDSA-CHACHA20-POLY1305     ECDH 253   ChaCha20    256      TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256      
-- |    xcca8   ECDHE-RSA-CHACHA20-POLY1305       ECDH 253   ChaCha20    256      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256        
-- |    x9d     AES256-GCM-SHA384                 RSA        AESGCM      256      TLS_RSA_WITH_AES_256_GCM_SHA384                    
-- |    x35     AES256-SHA                        RSA        AES         256      TLS_RSA_WITH_AES_256_CBC_SHA                       
-- |    xc02f   ECDHE-RSA-AES128-GCM-SHA256       ECDH 253   AESGCM      128      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256              
-- |    xc02b   ECDHE-ECDSA-AES128-GCM-SHA256     ECDH 253   AESGCM      128      TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256            
-- |    xc013   ECDHE-RSA-AES128-SHA              ECDH 253   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                 
-- |    xc009   ECDHE-ECDSA-AES128-SHA            ECDH 253   AES         128      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               
-- |    x9c     AES128-GCM-SHA256                 RSA        AESGCM      128      TLS_RSA_WITH_AES_128_GCM_SHA256                    
-- |    x2f     AES128-SHA                        RSA        AES         128      TLS_RSA_WITH_AES_128_CBC_SHA                       
-- |    x0a     DES-CBC3-SHA                      RSA        3DES        168      TLS_RSA_WITH_3DES_EDE_CBC_SHA                      
-- |   TLS 1.3  
-- |    x1302   TLS_AES_256_GCM_SHA384            ECDH 253   AESGCM      256      TLS_AES_256_GCM_SHA384                             
-- |    x1303   TLS_CHACHA20_POLY1305_SHA256      ECDH 253   ChaCha20    256      TLS_CHACHA20_POLY1305_SHA256                       
-- |    x1301   TLS_AES_128_GCM_SHA256            ECDH 253   AESGCM      128      TLS_AES_128_GCM_SHA256                             
-- |   
-- |    Done 2025-04-11 10:04:45 [  66s] -->> 142.250.178.4:443 (www.google.com) <<--
-- |   
-- |_  
-- 
-- Nmap done: 1 IP address (1 host up) scanned in 66.69 seconds
--
--@args ciphers Set to get testssl.sh to scan for ciphers too.
--
--@see testssl.nse

author = "Caddyshack2175"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.ssl

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local ciphers = stdnse.get_script_args(SCRIPT_NAME..".ciphers")
  local cmdresult
  local message
  
  if(ciphers == nil) then
    -- Run testssl.sh for Server Defaults and Vulnerbility checks
      message = "/usr/bin/testssl --warnings=off --color 0 -S -U " .. host.targetname .. ":" .. port.number
  else
    -- Run testssl.sh for Server Defaults and Vulnerbility checks
      message = "/usr/bin/testssl --warnings=off --color 0 -S -E -U " .. host.targetname .. ":" .. port.number
  end
  
  local cmd = io.popen(message)
  local cmdresult = cmd:read("*a")
  cmd:close()
  
  return stdnse.format_output(true, cmdresult)
end
