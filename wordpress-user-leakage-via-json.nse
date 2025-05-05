local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local json = require "json"
local string = require "string"
local table = require "table"


description = [[
Enumerate WordPress Users

To enumerate WordPress users using only the WordPress REST API JSON endpoint, this script uses the following URL formats:
- wp-json/wp/v2/users
- blog/wp-json/wp/v2/users
- wp/wp-json/wp/v2/users
- wordpress/wp-json/wp/v2/users
- cms/wp-json/wp/v2/users
- site/wp-json/wp/v2/users
- wp-json/users
- api/wp-json/wp/v2/users

** There are multiple veriations of the URI which this script endevors to cover.

These endpoints allows for the retrieval a collection of users from the WordPress site. However, this data should not be
publicly available, and in cases where the as correctly configured WordPress application is found, authenticatation is 
required access user/private data. When improperly configured this "user leakage" occurs, and user information is exposed.
]]

---
-- @usage
-- nmap -sT -p 443 --script wp-user-leakage-enum-via-json <target>
-- Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-05 22:51 BST
-- Nmap scan report for <target> (143.198.225.33)
-- Host is up (0.013s latency).
-- rDNS record for 143.198.225.33: 1361648.cloudwaysapps.com
-- 
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | wp-json: 
-- |   [!] WordPress JSON API endpoint found at: https://<target>/wp-json/wp/v2/users
-- |   [!] Extracted 1 WordPress users manually:
-- |   User 1: 
-- |     Name: webadmin
-- |     Username: webadmin
-- |_    ID: 1
-- 
-- Nmap done: 1 IP address (1 host up) scanned in 1.07 seconds
--
---

author = "Caddyshack2175"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

-- Check if the response body matches WordPress user JSON patterns
local function matches_wp_login(body)
  local patterns = {
    "id",
    "name",
    "avatar_urls",
    "description",
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
  -- Extended list of common paths to try
  local paths = {
    "/wp-json/wp/v2/users",
    "/blog/wp-json/wp/v2/users",
    "/wp/wp-json/wp/v2/users",
    "/wordpress/wp-json/wp/v2/users",
    "/cms/wp-json/wp/v2/users",
    "/site/wp-json/wp/v2/users",
    "/wp-json/users",
    "/api/wp-json/wp/v2/users"
  }

  -- Set headers and redirect options
  local options = {
    redirect_ok = 3,
    no_cache = true,
    header = {
      ["Content-Type"] = "application/json",
      ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Norton/133.0.0.0"
    },
  }
  -- Set number of in script args  --script-args="http-max-redirects=1"
  if stdnse.get_script_args("http-max-redirects") then
    options.redirect_ok = tonumber(stdnse.get_script_args("http-max-redirects"))
  end
  
  for _, path in ipairs(paths) do
    local response = http.get(host, port, path, options)
    -- Start checking responses
    if matches_status_code(response) and response.body and matches_wp_login(response.body) then
      local protocol = "http"
      if port.number == 443 or port.service == "https" then
        protocol = "https"
      end
      -- Craft URL where JSON was fond
      local url = string.format("%s://%s%s%s", protocol, stdnse.get_hostname(host), port.number ~= 80 and port.number ~= 443 and ":" .. port.number or "", path)
      
      -- Debug [1] - line to see raw response
      stdnse.debug1("Raw response: %s", response.body)
      
      -- Try to parse the JSON
      local status, parsed_data = pcall(function()
        return json.parse(response.body)
      end)
      
      -- If parsing succeeded
      if status and type(parsed_data) == "table" then
        table.insert(output, string.format("[!] WordPress JSON API endpoint found at: %s", url))
        
        -- Handle both array and object responses
        local users = parsed_data
        
        -- Check if users is a valid table with data
        if #users > 0 then
          table.insert(output, string.format("[!] Found %d WordPress users:", #users))
          
          -- Process each user
          for i, user in ipairs(users) do
            local user_entry = {}
            user_entry["ID"] = tostring(user.id or "N/A")
            user_entry["Name"] = tostring(user.name or "N/A")
            user_entry["Username"] = tostring(user.slug or "N/A")
            user_entry["URL"] = tostring(user.url or "N/A")
            user_entry["Description"] = tostring(user.description or "N/A")
            
            output[string.format("User %d", i)] = user_entry
          end
          
          return output
        else
          table.insert(output, "\n[+] No WordPress users found in the response")
        end
      else
        -- Debug [2] - Manual extraction attempt
        stdnse.debug1("JSON parsing failed, attempting manual extraction")
        -- If parsing failed, try manual extraction as fallback
        local users = {}
        -- Basic regex extraction for user data
        for id, name, slug in string.gmatch(response.body, '"id":(%d+).-"name":"([^"]-)".-"slug":"([^"]-)"') do
          local user = {
            id = id,
            name = name,
            slug = slug
          }
          table.insert(users, user)
        end
        
        if #users > 0 then
          table.insert(output, string.format("[!] WordPress JSON API endpoint found at: %s", url))
          table.insert(output, string.format("[!] Extracted %d WordPress users manually:", #users))
          
          for i, user in ipairs(users) do
            local user_entry = {}
            user_entry["ID"] = tostring(user.id or "N/A")
            user_entry["Name"] = tostring(user.name or "N/A")
            user_entry["Username"] = tostring(user.slug or "N/A")
            
            output[string.format("User %d", i)] = user_entry
          end
          
          return output
        else
          -- Show debugging info if no users found
          table.insert(output, "[*] Failed to parse JSON response")
          -- Print RAW response body, trucate to 500 chars for readability
          output["Raw Response"] = "\n...\n" .. response.body:sub(1, 500) .. "\n..."
        end
      end
      
      return output
    end
  end
end
