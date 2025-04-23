local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"


description = [[
Checks if a TLS/SSL server supports OCSP stapling.

OCSP stapling (formally known as the TLS Certificate Status Request extension) allows a server to provide OCSP responses to clients during the TLS handshake, which improves performance and privacy. This script attempts to establish a TLS connection with the OCSP status request extension and reports whether the server provided a stapled OCSP response. OCSP is in the process of sunsetting, with one certificate authority having already started the discontinuation of this service.
]]

---
-- This script attempts to establish a TLS connection with the OCSP status request extension and reports whether the server provided a stapled OCSP response.
-- This script uses the OpenSSL command on Linux systems and may not work on windows hosts. Check to verify OpenSSL is installed
-- * /usr/bin/openssl
-- 
-- The following toolout show if OCSP is enabled or not. 
-- Tool output below it is not;
-- -----------------------------------------------------------------------
-- nmap -sT -p 443 --script ssl-ocsp-stapling.nse www.google.com
-- Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-23 18:10 BST
-- Nmap scan report for www.google.com (142.250.187.196)
-- Host is up (0.016s latency).
-- Other addresses for www.google.com (not scanned): 2a00:1450:4009:81f::2004
-- rDNS record for 142.250.187.196: lhr25s33-in-f4.1e100.net
-- 
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | ssl-ocsp-stapling: 
-- |   title: OCSP Stapling
-- |   state: NOT ENABLED
-- |_  description: The server does not support OCSP stapling.
-- 
-- Nmap done: 1 IP address (1 host up) scanned in 0.41 seconds
-- -----------------------------------------------------------------------
-- 
-- If it is enabled the tooloutput should show the OCSP reponse data under evidence, shown below;
-- -----------------------------------------------------------------------
-- nmap -sT -p 443 --script ssl-ocsp-stapling.nse stackoverflow.com
-- Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-23 18:10 BST
-- Nmap scan report for stackoverflow.com (104.18.32.7)
-- Host is up (0.016s latency).
-- Other addresses for stackoverflow.com (not scanned): 172.64.155.249
-- 
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | ssl-ocsp-stapling: 
-- |   title: OCSP Stapling
-- |   state: ENABLED
-- |   description: The server supports OCSP stapling.
-- |   evidence: 
-- | ...
-- | ======================================
-- | OCSP Response Data:
-- |     OCSP Response Status: successful (0x0)
-- |     Response Type: Basic OCSP Response
-- |     Version: 1 (0x0)
-- |     Responder Id: C = US, O = Let's Encrypt, CN = E5
-- |     Produced At: Apr 21 15:53:00 2025 GMT
-- |     Responses:
-- |     Certificate ID:
-- |       Hash Algorithm: sha1
-- |       Issuer Name Hash: 1E11C0C9ACFDA453EF4B2F6A732115604D54ADB9
-- |       Issuer Key Hash: 99CD29C3A15826AF7A7A4C845A8F738860B0DFDE
-- |       Serial Number: 062FC77A3834C850C2B16BD192020B1259D7
-- |     Cert Status: good
-- |     This Update: Apr 21 15:53:00 2025 GMT
-- |     Next Update: Apr 28 15:52:58 2025 GMT
-- | 
-- |     Signature Algorithm: ecdsa-with-SHA384
-- |     Signature Value:
-- |         30:65:02:30:3e:1b:34:be:1c:90:7c:1d:19:77:a0:87:1d:9f:
-- |         11:8f:a7:64:16:ac:2d:9b:1f:da:98:ac:37:9d:3d:d9:05:27:
-- |         30:98:34:86:d6:89:6a:54:85:87:d4:4b:0c:fb:53:13:02:31:
-- |         00:80:c9:20:3e:21:94:66:a8:38:14:81:3a:3c:1c:e2:fa:5d:
-- |         55:85:ae:72:7b:d4:d3:af:4e:e3:76:39:e0:3a:a1:16:3e:d0:
-- |         37:0f:f3:a2:15:c2:5c:be:0c:09:df:34:b5
-- | ======================================
-- |_...
-- 
-- Nmap done: 1 IP address (1 host up) scanned in 0.48 seconds
-- -----------------------------------------------------------------------
-- 

author = "Caddyshack2175"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.ssl

action = function(host, port)
  local output = stdnse.output_table()
  local target = host.targetname or host.ip
 
  -- Prepare the OpenSSL command
  local command = "openssl s_client -connect " .. target .. ":" .. port.number .. " -status < /dev/null 2>&1"
  
  local cmd = io.popen(command)
  local cmdresult = cmd:read("*a")
  cmd:close()
  
  -- Parse the OpenSSL output to check for OCSP stapling
  if string.match(cmdresult, "OCSP Response Data:") then
    -- OCSP stapling is supported and a response is provided
    local ocsp_data = string.match(cmdresult, "OCSP response:%s*\n(.-)\n%-%-%-")

    output.title = "OCSP Stapling"
    output.state = "ENABLED"
    output.description = "The server supports OCSP stapling."
    
    if ocsp_data then
      output.evidence = "\n...\n" .. string.sub(ocsp_data, 1, 1110) .. "\n..." -- Truncate if too long
    end
    
    return output
    
  elseif string.match(cmdresult, "OCSP response: no response sent") then
    -- OCSP stapling is not supported or not enabled
    output.title = "OCSP Stapling"
    output.state = "NOT ENABLED"
    output.description = "The server does not support OCSP stapling."
    
    return output
  
  else
    -- Cannot determine OCSP stapling status
    if string.match(cmdresult, "connect:errno") then
      return "Connection error: Could not connect to the server"
    else
      return "Could not determine OCSP stapling status"
    end
  end
  
end
