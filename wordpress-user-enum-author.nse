local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
WordPress User Enumeration via Author URI

This script detects if a WordPress installation allows user enumeration through author archives. 
When a post is published on WordPress, the username or alias is shown as the author.
By accessing URLs like http://site.com/?author=1, attackers can enumerate WordPress usernames.  

References:
* https://security.stackexchange.com/questions/66272/wordpress-brute-force-attacker-knows-real-admin-username
* https://perishablepress.com/stop-user-enumeration-wordpress/
]]

---
-- @usage
-- nmap -p80 --script http-wordpress-user-enum.nse <target>
-- Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-04 00:11 BST
-- Nmap scan report for <target>
-- Host is up (0.00033s latency).
-- 
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | wordpress-user-enum-author: 
-- |   [!] WordPress User Enumeration via Author URI detected: Vulnerable
-- |   Found usernames: 
-- |_    admin
-- 
-- Nmap done: 1 IP address (1 host up) scanned in 1.61 seconds
-- 
--- 

author = "Caddyshack2175"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service({80, 443}, {"http", "https"})

action = function(host, port)
  local output = stdnse.output_table()
  local basepath = stdnse.get_script_args("http-wordpress-user-enum.basepath") or "/"
  local maxusers = tonumber(stdnse.get_script_args("http-wordpress-user-enum.maxusers")) or 50
  local usernames = {}
  local found = false
  
  -- Check if we need to add a trailing slash to the base path
  if not string.match(basepath, "/$") then
    basepath = basepath .. "/"
  end
  
  for i = 0, maxusers do
    local path = basepath .. "?author=" .. i
    local response = http.get(host, port, path, {redirect_ok=false})
    
    -- Check for user in body (using author-username pattern)
    if response.body then
      local username = string.match(response.body, 'author%-([^%s]+) author%-%d+')
      if username then
        table.insert(usernames, username)
        found = true
      end
    end
    
    -- Check for user in redirect Location header
    if response.header and response.header.location then
      local redirect_username = string.match(response.header.location, "/index%.php/author/([^/]+)/")
      if redirect_username then
        table.insert(usernames, redirect_username)
        found = true
      end
    end
  end
  
  if found then
    output["[!] WordPress User Enumeration via Author URI detected"] = "Vulnerable"
    output["Found usernames"] = usernames
    return output
  else
    if #usernames > 0 then
      output["[!] WordPress User Enumeration via Author URI detected"] = "Vulnerable"
      output["Found usernames"] = usernames
      return output
    else
      return "[+] WordPress User Enumeration via Author URI not detected"
    end
  end
end
