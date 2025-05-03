
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks for WordPress XMLRPC interface by sending a system.listMethods request.

XML-RPC predates WordPress, it has been present in the b2 blogging software, which was 
then forked to create WordPress back in 2003. XML-RPC was developed to enable communication 
between WordPress and other systems by standardizing those communications, using HTTP as 
the transport mechanism and XML as the datagram and encoding functionality.

This functionality is still included with WordPress despite the fact that XML-RPC is largely 
outdated. The xmlrpc.php file is typically stored in the root directory of the site.

References:
* https://kinsta.com/blog/xmlrpc-php/#why-you-should-disable-xmlrpcphp
* https://kinsta.com/blog/xmlrpc-php/#ddos-attacks-via-xmlrpc-pingbacks
* https://kinsta.com/blog/xmlrpc-php/#brute-force-attacks-via-xmlrpc
]]

---
-- @usage
-- nmap -sT -p 443 --script ./wp-xmlrpc-check.nse 192.168.1.88
-- Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-03 21:54 BST
-- Nmap scan report for 192.168.1.88
-- Host is up (0.00029s latency).
-- 
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | wp-xmlrpc-check: 
-- |   WordPress XMLRPC interface detected!: 
-- |   Methods found:: 
-- |     system.multicall
-- |     system.listMethods
-- |     system.getCapabilities
-- |     demo.addTwoNumbers
-- |     demo.sayHello
-- |     pingback.extensions.getPingbacks
-- |     pingback.ping
-- |     mt.publishPost
-- |     mt.getTrackbackPings
-- |     mt.supportedTextFilters
-- |     mt.supportedMethods
-- |     mt.setPostCategories
-- |     mt.getPostCategories
-- |     mt.getRecentPostTitles
-- |     mt.getCategoryList
-- |     metaWeblog.getUsersBlogs
-- |     metaWeblog.deletePost
-- |     metaWeblog.newMediaObject
-- |     metaWeblog.getCategories
-- |     metaWeblog.getRecentPosts
-- |     metaWeblog.getPost
-- |     metaWeblog.editPost
-- |     metaWeblog.newPost
-- |     blogger.deletePost
-- |     blogger.editPost
-- |     blogger.newPost
-- |     blogger.getRecentPosts
-- |     blogger.getPost
-- |     blogger.getUserInfo
-- |     blogger.getUsersBlogs
-- |     wp.restoreRevision
-- |     wp.getRevisions
-- |     wp.getPostTypes
-- |     wp.getPostType
-- |     wp.getPostFormats
-- |     wp.getMediaLibrary
-- |     wp.getMediaItem
-- |     wp.getCommentStatusList
-- |     wp.newComment
-- |     wp.editComment
-- |     wp.deleteComment
-- |     wp.getComments
-- |     wp.getComment
-- |     wp.setOptions
-- |     wp.getOptions
-- |     wp.getPageTemplates
-- |     wp.getPageStatusList
-- |     wp.getPostStatusList
-- |     wp.getCommentCount
-- |     wp.deleteFile
-- |     wp.uploadFile
-- |     wp.suggestCategories
-- |     wp.deleteCategory
-- |     wp.newCategory
-- |     wp.getTags
-- |     wp.getCategories
-- |     wp.getAuthors
-- |     wp.getPageList
-- |     wp.editPage
-- |     wp.deletePage
-- |     wp.newPage
-- |     wp.getPages
-- |     wp.getPage
-- |     wp.editProfile
-- |     wp.getProfile
-- |     wp.getUsers
-- |     wp.getUser
-- |     wp.getTaxonomies
-- |     wp.getTaxonomy
-- |     wp.getTerms
-- |     wp.getTerm
-- |     wp.deleteTerm
-- |     wp.editTerm
-- |     wp.newTerm
-- |     wp.getPosts
-- |     wp.getPost
-- |     wp.deletePost
-- |     wp.editPost
-- |     wp.newPost
-- |_    wp.getUsersBlogs
-- 
-- Nmap done: 1 IP address (1 host up) scanned in 0.11 seconds
-- 
---

author = "Caddyshack2175"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "vuln"}

portrule = shortport.port_or_service({80, 443}, {"http", "https"})

action = function(host, port)
  local output = stdnse.output_table()
  local path = "/xmlrpc.php"
  local payload = [[
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>]]

  local options = {
    header = {
      ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36",
      ["Content-Type"] = "text/xml",
    }
  }

  local response = http.post(host, port, path, options, nil, payload)

  if not response or response.status == nil then
    return nil
  end

  -- Check for a positive response status and content containing method strings
  if response.status == 200 and response.body and response.body:match("<string>.-</string>") then
    output["WordPress XMLRPC interface detected!"] = ""
    
    -- Extract method names
    local methods = {}
    for method in response.body:gmatch("<string>(.-)</string>") do
      table.insert(methods, method)
    end
    
    if #methods > 0 then
      output["Methods found:"] = methods
      return output
    end
  end
  
  return nil
end
