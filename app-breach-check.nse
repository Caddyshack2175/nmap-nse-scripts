local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
                                                                                                                 
description = [[
SSL/TLS BREACH Test of Web Application.

Checks if compression is enabled along with TLS/SSL, the site may be vulnerable to BREACH attacks. The BREACH vulnerability is a security issue that affects HTTPS 
when HTTP compression is used. It allows an attacker to extract sensitive information such as session cookies, CSRF tokens, and other sensitive data by exploiting
the compression oracle through HTTP compression, typically using the gzip or deflate algorithms.

The 'Vary: Accept-Encoding' header is used in HTTP responses to indicate that the server's response varies based on the value of the 'Accept-Encoding' request header. 
When this header is present, it indicates that the server is serving different versions of the content based on the compression method requested by the client. When 
HTTP compression is enabled, the 'Vary: Accept-Encoding' header can be used to mitigate the BREACH attack by ensuring that the server serves different versions of the 
content based on the compression method requested. This can prevent the attacker from being able to consistently measure the size of compressed responses, which is a 
key part of the BREACH attack.

However, disabling HTTP compression entirely is often not a practical solution since it is widely used to improve bandwidth efficiency and transmission speeds.

To mitigate the BREACH attack while maintaining HTTP compression, several strategies can be employed:
- Protecting vulnerable pages with a CSRF token.
- Adding random bytes to the response to hide the actual compressed length.
- Separating sensitive data from pages where user input is displayed.
- Disabling compression-only if the referrer is not the own application.

These mitigations aim to make it more difficult for an attacker to accurately measure the compressed response sizes and thus reduce the effectiveness of the BREACH attack.
]]

---
-- @usage
-- nmap -sT -p 443 --script breach.nse login.wordpress.org
-- Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-03 15:59 BST
-- Nmap scan report for login.wordpress.org (198.143.164.252)
-- Host is up (0.012s latency).
-- rDNS record for 198.143.164.252: wordpress.org
-- 
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | breach: 
-- | 
-- | [+] Port: 443 - https://login.wordpress.org:443/
-- | [+] HTTP Status Code: 200
-- | 
-- | BREACH Test Response Headers:
-- |   alt-svc: h3=":443"; ma=86400
-- |   cache-control: no-cache, must-revalidate, max-age=0, no-store, private
-- |   connection: close
-- |   content-encoding: br
-- |   content-type: text/html; charset=UTF-8
-- |   date: Sat, 03 May 2025 14:59:27 GMT
-- |   expires: Wed, 11 Jan 1984 05:00:00 GMT
-- |   link: <https://login.wordpress.org/wp-json/>; rel="https://api.w.org/"
-- |   server: nginx
-- |   set-cookie: wporg_locale=en_US; expires=Sun, 03-May-2026 14:59:27 GMT; Max-Age=31536000; path=/; domain=.wordpress.org; secure
-- |   transfer-encoding: chunked
-- |   vary: Accept-Encoding
-- |   x-frame-options: SAMEORIGIN
-- |   x-nc: MISS ord 2
-- |   x-olaf: \xE2\x9B\x84
-- | 
-- | Security Issues:
-- |   [!] Potential BREACH vulnerability: HTTPS with compression enabled (br)
-- |   [*] 'Vary: Accept-Encoding' header is present, but this does not mitigate the BREACH vulnerability
-- |_
-- 
-- Nmap done: 1 IP address (1 host up) scanned in 0.53 seconds
---

author = "Caddyshack2175"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Works on any port that has http* or has a service match to SSL
portrule = function(host, port)
  return port.state == "open" and (port.service == "https" or 
         port.service:match("^https%-") or port.service:match("^ssl/http"))
end

action = function(host, port)
    -- Set tables and variable used in the action
    local output = {}
    local path = "/"
    local target = host.targetname or host.ip
    local protocol = "http"
    local is_https = false

    -- Second check to make sure HTTPS is detected
    if port.number == 443 or port.service == "https" then
        protocol = "https"
        is_https = true
    end

    local url = protocol .. "://" .. target .. ":" .. port.number .. path
    -- Find missing security headers
    local issues = {}
    -- Add target information
    table.insert(output, "\n")
    table.insert(output, "[+] Port: " .. port.number .. " - " .. url)
    
    -- Make a single request with Accept-Encoding header for BREACH test
    local options = {
      header = {
        ["Accept-Encoding"] = "gzip, deflate, br"
      }
    }
    
    local response = http.get(host, port, path, options)
    
    if not response or not response.status then
        return "[!] Failed to retrieve response from server"
    end
    
    -- Add status code information
    table.insert(output, "[+] HTTP Status Code: " .. response.status .. "\n")
    
    -- Process headers
    local headers_found = {}
    
    -- Add only the BREACH Test Response Headers section
    table.insert(output, "BREACH Test Response Headers:")
    
    -- Sort header names alphabetically for consistent output
    local header_names = {}
    for name, value in pairs(response.header) do
        table.insert(header_names, name)
        -- Store the headers in lowercase for case-insensitive checks later
        headers_found[string.lower(name)] = value
    end
    table.sort(header_names)
    
    -- Display headers
    for _, name in ipairs(header_names) do
        table.insert(output, "  " .. name .. ": " .. response.header[name])
    end
    
    -- Check for Vary header
    local has_vary_header = false
    if headers_found["vary"] and 
       string.match(string.lower(headers_found["vary"]), "accept%-encoding") then
        has_vary_header = true
    end
    
    -- Check for compression and BREACH vulnerability
    local compression_enabled = false
    local compression_type = nil
    
    -- Check if content-encoding header indicates compression
    if headers_found["content-encoding"] then
        local encoding = string.lower(headers_found["content-encoding"])
        if string.match(encoding, "gzip") or string.match(encoding, "deflate") or string.match(encoding, "br") then
            compression_enabled = true
            compression_type = headers_found["content-encoding"]
            
            -- If HTTPS and compression are both enabled, mark as potentially vulnerable
            -- Note: Vary header doesn't mitigate BREACH, so we flag it regardless
            if is_https then
                table.insert(issues, "  [!] Potential BREACH vulnerability: HTTPS with compression enabled (" .. compression_type .. ")")
            end
        end
    end
    
    -- Check if Vary header is missing when compression is enabled
    -- We'll flag this as a secondary issue, but note it's not a BREACH mitigation
    if compression_enabled and not has_vary_header then
        table.insert(issues, "  [!] Missing 'Vary: Accept-Encoding' header with compression enabled (note: this does not mitigate BREACH)")
    end

    -- Output security issues if found
    if #issues > 0 then
        table.insert(output, "\nSecurity Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, issue)
        end
        
        -- Add a note about the Vary header if it's present
        if compression_enabled and has_vary_header then
            table.insert(output, "  [*] 'Vary: Accept-Encoding' header is present, but this does not mitigate the BREACH vulnerability")
        end

    else
        if is_https then
            if compression_enabled then
                table.insert(output, "\n[!] Potential BREACH vulnerability: HTTPS with compression enabled (" .. compression_type .. ")")
            else
                table.insert(output, "\n[+] No compression detected - not vulnerable to BREACH")
            end
        else
            table.insert(output, "\n[+] Not using HTTPS - BREACH attack not applicable")
        end
    end

    table.insert(output, "\n")

    return table.concat(output, "\n")
end
