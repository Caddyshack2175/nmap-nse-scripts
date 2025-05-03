local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
WordPress Login URL/Interface Exposed

The login page is the gateway between WordPress website and the admin or management dashboard of the site, typically known as the "admin area". 
A compromise on the interface and an attacker will gain control of the web-site, install back-doors, possibly gain control of the host.

References:
* https://kinsta.com/blog/wordpress-login-url/#change-your-wordpress-login-with-a-plugin
* https://kinsta.com/blog/wordpress-login-url/#change-your-wordpress-login-page-editing-your-htaccess-file
]]

---
-- @usage
-- nmap -sT -p 443 --script ./wp-login-interface-exposed.nse <target>
-- Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-03 22:06 BST
-- Nmap scan report for 192.168.1.88
-- Host is up (0.00027s latency).
-- 
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | wp-login-interface-exposed: 
-- |_  [!] WordPress login page found : https://192.168.1.88/wp-login.php
-- 
-- Nmap done: 1 IP address (1 host up) scanned in 0.09 seconds
-- 
---

author = "Caddyshack2175"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service({80, 443}, {"http", "https"})

-- Check if the response body matches WordPress login page patterns
local function matches_wp_login(body)
  local patterns = {
    "Username or Email Address",
    "Password",
    "Lost your password?",
    "Remember Me"
  }
  
  for _, pattern in ipairs(patterns) do
    if not string.match(body, pattern) then
      return false
    end
  end
  
  return true
end

-- Check if the response status code matches 200
local function matches_status_code(response)
  return response and response.status == 200
end

action = function(host, port)
  local output = stdnse.output_table()
  local paths = {
    "/wp-login.php",
    "/wp-admin/",
    "/login/",
    "/admin/"
  }
  
  local options = {
    redirect_ok = 3,  -- Follow up to 3 redirects by default
    no_cache = true
  }
  
  -- Allow user to override the default redirect limit
  if stdnse.get_script_args("http-max-redirects") then
    options.redirect_ok = tonumber(stdnse.get_script_args("http-max-redirects"))
  end
  
  for _, path in ipairs(paths) do
    local response = http.get(host, port, path, options)
    
    -- Check both matchers status code 200 AND login page patterns
    if matches_status_code(response) and response.body and matches_wp_login(response.body) then
      -- Build the full URL that was found
      local protocol = "http"
      if port.number == 443 or port.service == "https" then
        protocol = "https"
      end
      
      local url = string.format("%s://%s%s%s", protocol, stdnse.get_hostname(host), port.number ~= 80 and port.number ~= 443 and ":" .. port.number or "", path)

      output["[!] WordPress login page found"] = url
      return output
    end
  end
  
  return nil  -- Return nil when nothing is found
end
