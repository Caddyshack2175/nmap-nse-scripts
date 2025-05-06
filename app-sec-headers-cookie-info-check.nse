local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
                                                                                                                 
description = [[
Checks if a web server implements recommended HTTP security headers.

This script examines the HTTP response headers of a web server and reports on the
presence or absence of important security headers such as:
- HTTP Strict Transport Security (HSTS) (HTTPS only)
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Header version information 
- Cookie security analysis
- And more

The script performs recursive cookie inspection for each Set-Cookie header, checking:
- Secure and HttpOnly flags
- SameSite attribute configuration
- Parent domain cookie settings that could expose data to other subdomains
- Session cookies (missing Expires/Max-Age)
- Long-lived cookies (excessive Expires/Max-Age)
- Potentially sensitive cookies

]]

---
-- @usage
-- nmap -sT -p 443 --script app-sec-headers-cookie-info-check.nse login.wordpress.org
-- Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-03 16:20 BST
-- Nmap scan report for login.wordpress.org (198.143.164.252)
-- Host is up (0.012s latency).
-- rDNS record for 198.143.164.252: wordpress.org
-- 
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- |  app-sec-headers-cookie-info-check: 
-- |  
-- |  [+] Port: 443 - https://login.wordpress.org:443/
-- |  [+] HTTP Status Code: 200
-- |  HTTP Headers:
-- |    alt-svc: h3=":443"; ma=86400
-- |    cache-control: no-cache, must-revalidate, max-age=0, no-store, private
-- |    connection: close
-- |    content-type: text/html; charset=UTF-8
-- |    date: Sat, 03 May 2025 15:20:01 GMT
-- |    expires: Wed, 11 Jan 1984 05:00:00 GMT
-- |    link: <https://login.wordpress.org/wp-json/>; rel="https://api.w.org/"
-- |    server: nginx
-- |    set-cookie: wporg_locale=en_US; expires=Sun, 03-May-2026 15:20:01 GMT; Max-Age=31536000; path=/; domain=.wordpress.org; secure
-- |    transfer-encoding: chunked
-- |    vary: Accept-Encoding
-- |    x-frame-options: SAMEORIGIN
-- |    x-nc: MISS ord 2
-- |    x-olaf: \xE2\x9B\x84
-- |  
-- |  Security Issues:
-- |    [!] Referrer-Policy Header Missing
-- |    [!] Access-Control-Allow-Origin Header Missing
-- |    [!] HSTS Header Missing
-- |    [!] Permissions-Policy Header Missing
-- |    [!] CSP Header Missing
-- |    [!] X-Content-Type-Options Header Missing
-- |    [!] Cross-Origin-Opener-Policy Header Missing
-- |    [!] Cookie 'wporg_locale' has no SameSite attribute
-- |    [!] Cookie 'wporg_locale' has no HttpOnly flag
-- |    [!] Cookie 'wporg_locale' has excessive Max-Age: 31536000 seconds (> 6 months)
-- |    [!] Cookie 'wporg_locale' set to parent domain 'wordpress.org' (host: login.wordpress.org)
-- |    [!] Parent domain cookie 'wporg_locale' lacks HttpOnly flag
-- |    [!] Parent domain cookie 'wporg_locale' has risky SameSite setting: not set
-- |    [!] Version information in Server: nginx
-- |    [!] Version info in link: <https://login.wordpress.org/wp-json/>; rel="https://api.w.org/"
-- |    [!] Version info in set-cookie: wporg_locale=en_US; expires=Sun, 03-May-2026 15:20:01 GMT; Max-Age=31536000; path=/; domain=.wordpress.org; secure
-- | _
-- 
-- Nmap done: 1 IP address (1 host up) scanned in 0.63 seconds
-- 
-- 
---

author = "Caddyshack2175"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Works on any port that has http* or has a service match to SSL
portrule = function(host, port)
  return port.state == "open" and (port.service == "http" or port.service == "https" or 
         port.service:match("^http%-") or port.service:match("^ssl/http"))
end

-- Function to detect version information in HTTP headers
function detect_version_headers(headers)
  local findings = {}
  
  -- Headers that commonly disclose information
  local version_headers = {
    -- Server software and version
    "Server",
    "X-Powered-By",
    -- Web frameworks and technologies
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Version",
    "X-Generator",
    -- CMS versions
    "X-Drupal-Version",
    "X-Wordpress-Version",
    "X-Joomla-Version",
    -- Programming languages and environments
    "X-PHP-Version",
    "X-Ruby-Version",
    "X-Python-Version",
    "X-Node-Version",
    -- Caching and middleware
    "X-Varnish-Version",
    "X-Varnish",
    "X-Cache",
    "X-Proxy",
    -- Application info
    "X-Application-Version",
    "X-Framework-Version",
    -- AWS and cloud info
    "X-Amz-Cf-Id",
    "X-Azure-Ref",
    "X-Served-By",
    -- Web server details
    "X-Backend-Server",
    "Via",
    -- Debugging info
    "X-Debug",
    "X-Runtime"
  }
  
  -- Version pattern to match version strings like 1.2.3, 4.5-6, etc.
  local version_pattern = "[%d%.]+[%-%d%.]*"
  
  -- Common technology keywords to look for
  local tech_keywords = {
    "apache", "nginx", "iis", "tomcat", "jetty", "nodejs", "express",
    "php", "python", "ruby", "perl", "java", ".net", "wordpress", 
    "drupal", "joomla", "django", "laravel", "rails", "struts"
  }
  
  -- Check each header
  for _, header_name in ipairs(version_headers) do
    local header_value = headers[string.lower(header_name)]
    if header_value then
      -- Direct match on version headers
      table.insert(findings, "  [!] Version information in " .. header_name .. ": " .. header_value)
    end
  end
  
  -- Additional check for any header that might contain version info
  for header_name, header_value in pairs(headers) do
    -- Skip headers we've already reported
    local already_reported = false
    for _, vh in ipairs(version_headers) do
      if string.lower(header_name) == string.lower(vh) then
        already_reported = true
        break
      end
    end
    
    if not already_reported then
      -- Check if header contains version numbers or keywords
      if string.match(header_value, version_pattern) or 
         string.find(string.lower(header_value), "version") then
        for _, keyword in ipairs(tech_keywords) do
          if string.find(string.lower(header_value), keyword) then
            table.insert(findings, "  [!] Version info in " .. header_name .. ": " .. header_value)
            break
          end
        end
      end
    end
  end
  
  return findings
end

-- Function to inspect cookies and their attributes
function inspect_cookies(response, host)
  local findings = {}
  
  -- Get all cookies from response headers
  local all_cookies = {}
  
  -- Get Set-Cookie headers - might be string, table, or nil
  local set_cookie = response.header["Set-Cookie"] or response.header["set-cookie"]
  
  -- If no cookies found, return empty findings
  if not set_cookie then
    return findings
  end
  
  -- Normalize to table format for consistent processing
  if type(set_cookie) == "string" then
    set_cookie = {set_cookie}
  end
  
  -- Get the hostname for parent domain checks
  local hostname = host.targetname or host.ip
  
  -- Process each Set-Cookie header
  for _, cookie_header in ipairs(set_cookie) do
    -- Each cookie should be a string like: name=value; attr1=val1; attr2; attr3=val3
    local cookie_name = string.match(cookie_header, "^([^=]+)=")
    
    if cookie_name then
      -- Extract attributes with case-insensitive matching
      local samesite = string.match(cookie_header:lower(), "samesite=([^;]+)")
      local secure = string.match(cookie_header:lower(), "secure[;]?")
      local httponly = string.match(cookie_header:lower(), "httponly[;]?")
      local domain = string.match(cookie_header:lower(), "domain=([^;]+)")
      -- local path = string.match(cookie_header:lower(), "path=([^;]+)")
      local expires = string.match(cookie_header:lower(), "expires=([^;]+)")
      local max_age = string.match(cookie_header:lower(), "max%-age=([^;]+)")
      
      -- Check for SameSite attribute
      if samesite then
        -- Trim any whitespace
        samesite = string.gsub(samesite, "^%s*(.-)%s*$", "%1")
        
        -- Check for potentially insecure SameSite configuration
        if samesite ~= "strict" and samesite ~= "lax" and samesite ~= "none" then
          table.insert(findings, string.format("  [!] Cookie '%s' has invalid SameSite value: %s", cookie_name, samesite))
        elseif samesite == "none" and not secure then
          table.insert(findings, string.format("  [!] Cookie '%s' has SameSite=None but lacks Secure flag", cookie_name))
        end
      else
        table.insert(findings, string.format("  [!] Cookie '%s' has no SameSite attribute", cookie_name))
      end
      
      -- Check for Secure flag
      if not secure then
        table.insert(findings, string.format("  [!] Cookie '%s' has no Secure flag", cookie_name))
      end
      
      -- Check for HttpOnly flag
      if not httponly then
        table.insert(findings, string.format("  [!] Cookie '%s' has no HttpOnly flag", cookie_name))
      end
      
      -- Check for session cookies (no Expires or Max-Age)
      if not expires and not max_age then
        table.insert(findings, string.format("  [!] Cookie '%s' is a session cookie (no Expires or Max-Age)", cookie_name))
      end
      
      -- Check for very long-lived cookies
      if max_age and tonumber(max_age) and tonumber(max_age) > 15768000 then -- > no more than 6 months
        table.insert(findings, string.format("  [!] Cookie '%s' has excessive Max-Age: %s seconds (> 6 months)", 
          cookie_name, max_age))
      end
      
      -- Check for overly permissive paths ** Removed this check as most paths are typically on root branches
      -- if not path or path == "/" then
      --   table.insert(findings, string.format("  [!] Cookie '%s' has overly permissive path: %s", 
      --     cookie_name, path or "/"))
      -- end
      
      -- Check for parent domain cookie setting
      if domain then
        -- Remove any leading dot and trim whitespace
        domain = string.gsub(domain, "^%.", "")
        domain = string.gsub(domain, "^%s*(.-)%s*$", "%1")
        
        -- First, check if domain attribute is valid (contains at least one dot)
        if not string.find(domain, "%.") then
          table.insert(findings, string.format("  [!] Cookie '%s' has invalid domain: %s", cookie_name, domain))
        else
          -- Check if domain is a parent domain of the host
          if hostname and hostname ~= domain then
            -- Check if hostname ends with the domain (parent domain check)
            local hostname_length = string.len(hostname)
            local domain_length = string.len(domain)
            
            if hostname_length > domain_length and 
               string.sub(hostname, -domain_length) == domain and
               string.sub(hostname, -domain_length-1, -domain_length-1) == "." then
              -- This is a parent domain cookie
              table.insert(findings, string.format("  [!] Cookie '%s' set to parent domain '%s' (host: %s)", 
                cookie_name, domain, hostname))
              
              -- Check if it's secure
              if not secure then
                table.insert(findings, string.format("  [!] Parent domain cookie '%s' lacks Secure flag", cookie_name))
              end
              
              -- Check if it's HttpOnly
              if not httponly then
                table.insert(findings, string.format("  [!] Parent domain cookie '%s' lacks HttpOnly flag", cookie_name))
              end
              
              -- Check if SameSite is properly configured for parent domain cookies
              if not samesite or samesite == "none" then
                table.insert(findings, string.format("  [!] Parent domain cookie '%s' has risky SameSite setting: %s", 
                  cookie_name, samesite or "not set"))
              end
            end
          end
        end
      end
      
      -- Check for cookie containing potentially sensitive information in the name
      local sensitive_terms = {"session", "auth", "secure", "login", "pass", "admin", "user", "token", "key", "secret", "csrf", "xsrf"}
      for _, term in ipairs(sensitive_terms) do
        if string.find(string.lower(cookie_name), term) then
          -- Found potentially sensitive cookie
          if not secure then
            table.insert(findings, string.format("  [!] Potentially sensitive cookie '%s' lacks Secure flag", cookie_name))
          end
          if not httponly then
            table.insert(findings, string.format("  [!] Potentially sensitive cookie '%s' lacks HttpOnly flag", cookie_name))
          end
          break
        end
      end
    end
  end
  
  return findings
end

action = function(host, port)
  -- Set tables and variable used in the action
  if stdnse.get_script_args("URI") then
    URI = string.format(stdnse.get_script_args("URI"))
  end

  local output = {}
  local path = URI or "/"
  local target = host.targetname or host.ip
  local protocol = "http"
  local is_https = false

  -- Use HTTPS for port 443
  if port.number == 443 or port.service == "https" then
    protocol = "https"
    is_https = true
  end

  if stdnse.get_script_args("https") then
    protocol = "https"
    is_https = true
  end

  -- Set headers and redirect options
  local referer_header_url =  protocol .. "://" .. target .. ":" .. port.number .. path
  
  local options = {
    redirect_ok = 3,
    header = {
      ["Host"] = target .. ":" .. port.number,
      ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36",
      ["Accept-Language"] = "en-GB",
      ["Referer"] = referer_header_url
    },
  }
  -- Debug [1] - Check out going headers are set
  stdnse.debug1("Request headers and options configured => %s", options)
  local url = protocol .. "://" .. target .. ":" .. port.number .. path
  
  -- Add target information
  table.insert(output, "\n")
  table.insert(output, "[+] Port: " .. port.number .. " - " .. url)
  -- If HTTPS is set, set service to HTTPS
  if is_https then
    port.service = "https"
  end
  -- Make standard HTTP request
  local response = http.get(host, port, path, options)
  
  if not response or not response.status then
    return "[!] Failed to retrieve response from server"
  end
  
  -- Add status code information
  table.insert(output, "[+] HTTP Status Code: " .. response.status)
  
  -- Add headers section
  table.insert(output, "HTTP Headers:")
  
  -- Process headers
  local headers_found = {}
  
  -- Sort header names alphabetically for consistent output
  local header_names = {}
  for name, _ in pairs(response.header) do
    table.insert(header_names, name)
  end
  table.sort(header_names)
  
  -- Format and add headers
  for _, name in ipairs(header_names) do
    local value = response.header[name]
    if type(value) == "table" then
      value = table.concat(value, ", ")
    end
    headers_found[string.lower(name)] = value
    table.insert(output, "  " .. name .. ": " .. value)
  end
  
  -- Add an empty line after headers
  table.insert(output, "")
  
  -- Define security headers to check based on protocol
  local security_headers = {
    ["Content-Security-Policy"] = "CSP Header Missing",
    ["X-Frame-Options"] = "X-Frame-Options Header Missing",
    ["X-Content-Type-Options"] = "X-Content-Type-Options Header Missing",
    ["Referrer-Policy"] = "Referrer-Policy Header Missing",
    ["Access-Control-Allow-Origin"] = "Access-Control-Allow-Origin Header Missing",
    ["Cross-Origin-Opener-Policy"] = "Cross-Origin-Opener-Policy Header Missing",
    ["Permissions-Policy"] = "Permissions-Policy Header Missing",
  }

  -- Only check for HSTS if using HTTPS
  if is_https then
    security_headers["Strict-Transport-Security"] = "HSTS Header Missing"
  end

  -- Find missing security headers
  local issues = {}
  
  -- HSTS verify header configuration
  if is_https and headers_found["strict-transport-security"] then
    local hsts_value = headers_found["strict-transport-security"]
    local max_age = tonumber(string.match(hsts_value, "max%-age=(%d+)") or "0")
    local has_subdomains = string.match(hsts_value, "includeSubDomains") ~= nil
    
    if max_age < 31536000 then
      table.insert(issues, "  [!] HSTS Header Missconfigured: max-age too short (should be at least 31536000 seconds/1 year)")
    end
    
    if not has_subdomains then
      table.insert(issues, "  [!] HSTS Header Misscsonfigured: missing includeSubDomains directive")
    end
  end
  
  for header_name, description in pairs(security_headers) do
    local lower_name = string.lower(header_name)
    if not headers_found[lower_name] then
      table.insert(issues, "  [!] " .. description)
    end
  end

  -- Check cookies for security issues
  local cookie_issues = inspect_cookies(response, host)
  for _, issue in ipairs(cookie_issues) do
    table.insert(issues, issue)
  end

  -- Check for misconfigured headers
  if headers_found["x-content-type-options"] and 
     headers_found["x-content-type-options"] ~= "nosniff" then
    table.insert(issues, "  [!] X-Content-Type-Options miss-configured")
  end
  
  if headers_found["x-frame-options"] then
    local frame_value = string.upper(headers_found["x-frame-options"])
    if frame_value ~= "DENY" and frame_value ~= "SAMEORIGIN" then
      table.insert(issues, "  [!] X-Frame-Options miss-configured")
    end
  end

  if headers_found["x-xss-protection"] then
    local frame_value = string.upper(headers_found["x-xss-protection"])
    if frame_value ~= "0" then
      table.insert(issues, "  [!] X-XSS-Protection miss-configured")
    end
  end

  -- Check for version information disclosure in headers
  local version_issues = detect_version_headers(headers_found)
  for _, issue in ipairs(version_issues) do
    table.insert(issues, issue)
  end

  -- Add security issues section
  if #issues > 0 then
    table.insert(output, "Security Issues:")
    for _, issue in ipairs(issues) do
      table.insert(output, issue)
    end
  else
    table.insert(output, "Security Headers: All recommended security headers are properly configured.")
  end
  
  table.insert(output, "\n")

  return table.concat(output, "\n")
end
