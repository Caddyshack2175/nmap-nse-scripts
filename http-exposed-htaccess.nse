local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Checks if a web server exposes its .htaccess file. The script specifically looks for .htaccess files, not only by 200 response status, but also by searching for the following directives in the file:
1. Start with the tag "<Files .htaccess>"
2. Contain "IfModule" directive
Exposure of this file could reveal sensitive server configuration files being exposed.
]]

author = "Caddyshack2175"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "vuln"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  local output = stdnse.output_table()
  local vulnerability_found = false
  local path = "/.htaccess"
  local uri = path
  local options = {redirect_ok = false}
  
  stdnse.debug1("Checking for exposed .htaccess file at %s", uri)
  
  local response = http.get(host, port, uri, options)
  
  if not response or not response.status then
    stdnse.debug1("No HTTP response from %s", uri)
    return nil
  end
  
  if response.status ~= 200 then
    stdnse.debug1("Server returned status %d for %s", response.status, uri)
    return nil
  end
  
  -- Check if response body exists
  if not response.body then
    stdnse.debug1("Response body is empty for %s", uri)
    return nil
  end
  
  -- Use regex to look for the specific patterns in the .htaccess file
  local has_files_tag = string.match(response.body, "<Files%s+.htaccess>") ~= nil
  local has_ifmodule = string.match(response.body, "IfModule") ~= nil
  
  if has_files_tag and has_ifmodule then
    vulnerability_found = true
    output.title = "Exposed .htaccess file"
    output.state = "VULNERABLE"
    output.description = "The web server at " .. host.ip .. " exposes its .htaccess file, which contains sensitive configuration directives."
    local content_preview = "\n\n" .. response.body
    output.details = "Found .htaccess file containing both '<Files .htaccess>' tag and 'IfModule' directive."
    output.evidence = content_preview
    
    return output
  end
  
  return nil
end
