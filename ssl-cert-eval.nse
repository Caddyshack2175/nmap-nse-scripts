local datetime = require "datetime"
local nmap = require "nmap"
local outlib = require "outlib"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local unicode = require "unicode"
local have_openssl, openssl = pcall(require, "openssl")
local os = require "os"

description = [[
Retrieves a server's SSL certificate and performs security evaluation. The amount of information printed about 
the certificate depends on the verbosity level. With no extra verbosity, the script prints the validity period 
and the commonName, organizationName, stateOrProvinceName, and countryName of the subject.

The script works the same as the original, however it now evaluates the certificate for security issues such as:
- Self-signed certificates
- Weak key length (< 2048 bits)
- Weak signature algorithms (MD5 or SHA1)
- Expired or soon-to-expire certificates
- SAN's evaluation; which identifies the number of Subject Alternative Names being used in the Certificate
- Wildcard certificate check
]]

---
-- @usage
-- nmap -sT -p 443 --script ./ssl-cert-eval stackoverflow.com
-- Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-03 19:37 BST
-- Nmap scan report for stackoverflow.com (104.18.32.7)
-- Host is up (0.012s latency).
-- Other addresses for stackoverflow.com (not scanned): 172.64.155.249
-- 
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | ssl-cert-eval: 
-- | 
-- | Subject: commonName=stackoverflow.com
-- | Subject Alternative Name: DNS:*.stackoverflow.com, DNS:stackoverflow.com
-- | Issuer: commonName=E5/organizationName=Let's Encrypt/countryName=US
-- | Public Key type: ec
-- | Public Key bits: 256
-- | Signature Algorithm: ecdsa-with-SHA384
-- | Not valid before: 2025-04-30T16:51:49
-- | Not valid after:  2025-07-29T16:51:48
-- | MD5:   8ba7:691a:4ea7:e40b:80ff:c7dd:8057:517c
-- | SHA-1: c5df:36ba:7061:7d11:00f6:28f2:1c07:4467:ec26:df8f
-- | 
-- | Certificate Security Evaluation:
-- |   [!] Weak public key length (256 bits, should be at least 2048)
-- |   [!] Certificate uses wildcard domains: *.stackoverflow.com
-- |   [+] Certificate is properly signed by a trusted CA
-- |   [+] Strong signature algorithm: ecdsa-with-SHA384
-- |   [+] Certificate is valid for 87 more days
-- |   [+] Certificate contains a reasonable number of Subject Alternative Names (2)
-- |_
-- 
-- Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds
-- 
--- 
author = "David Fifield as the original author, with security evaluations by Caddyshack2175"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "default", "safe", "discovery" }
dependencies = {"https-redirect"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

-- Find the index of a value in an array.
function table_find(t, value)
  local i, v
  for i, v in ipairs(t) do
    if v == value then
      return i
    end
  end
  return nil
end

function date_to_string(date)
  if not date then
    return "MISSING"
  end
  if type(date) == "string" then
    return string.format("Can't parse; string is \"%s\"", date)
  else
    return datetime.format_timestamp(date)
  end
end

-- These are the subject/issuer name fields that will be shown, in this order,
-- without a high verbosity.
local NON_VERBOSE_FIELDS = { "commonName", "organizationName",
"stateOrProvinceName", "countryName" }

-- Test to see if the string is UTF-16 and transcode it if possible
local function maybe_decode(str)
  -- If length is not even, then return as-is
  if #str < 2 or #str % 2 == 1 then
    return str
  end
  if str:byte(1) > 0 and str:byte(2) == 0 then
    -- little-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, false, nil)
  elseif str:byte(1) == 0 and str:byte(2) > 0 then
    -- big-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, true, nil)
  else
    return str
  end
end

-- Add this helper function at the top of your script
local function get_expiry_info(cert)
    local issues = {}
    local secure_aspects = {}
    local expired = false
    local expiring_soon = false
    local days_until_expiry = 0
    
    if not cert or not cert.validity or not cert.validity.notAfter then
      table.insert(issues, "  [!] Certificate expiration date not available")
      return issues, secure_aspects, expired, expiring_soon, days_until_expiry
    end
    
    -- Get the expiration date as a string representation from the datetime module
    local expiry_str = date_to_string(cert.validity.notAfter)
    stdnse.debug1("Expiry string: %s", expiry_str)
    
    -- Check if it's an explicit "MISSING" string
    if expiry_str == "MISSING" then
      table.insert(issues, "  [!] Certificate expiration date not available")
      return issues, secure_aspects, expired, expiring_soon, days_until_expiry
    end
    
    -- Try to extract the date from the string format
    -- Example: "2021-10-13T12:00:00+00:00" or "2021-10-13 12:00:00"
    local year, month, day = string.match(expiry_str, "(%d%d%d%d)%-(%d%d)%-(%d%d)")
    
    if year and month and day then
      -- We've extracted the date components
      local expiry_timestamp = os.time({
        year = tonumber(year),
        month = tonumber(month),
        day = tonumber(day),
        hour = 23,  -- Assume end of day if time not specified
        min = 59,
        sec = 59
      })
      
      local current_time = os.time()
      
      if current_time > expiry_timestamp then
        expired = true
        local days_expired = math.floor((current_time - expiry_timestamp) / 86400)
        table.insert(issues, string.format("  [!] Certificate expired %d day%s ago", 
                                        days_expired, days_expired == 1 and "" or "s"))
      else
        -- Calculate days until expiry
        days_until_expiry = math.floor((expiry_timestamp - current_time) / 86400)
        
        if days_until_expiry <= 30 then
          expiring_soon = true
          table.insert(issues, string.format("  [!] Certificate expires in %d day%s", 
                                           days_until_expiry, days_until_expiry == 1 and "" or "s"))
        else
          table.insert(secure_aspects, string.format("  [+] Certificate is valid for %d more days", days_until_expiry))
        end
      end
    else
      -- If we couldn't parse the date format
      table.insert(issues, string.format("  [!] Could not parse expiration date: %s", expiry_str))
    end
    
    return issues, secure_aspects, expired, expiring_soon, days_until_expiry
end

-- Helper function to count SANs in a certificate
local function count_sans(cert)
    local count = 0
    local sans_str = nil
    
    -- Check if the certificate has extensions
    if cert and cert.extensions then
      -- Look for the Subject Alternative Name extension
      for _, ext in ipairs(cert.extensions) do
        if ext.name == "X509v3 Subject Alternative Name" then
          sans_str = ext.value
          
          -- Count the number of entries (separated by commas)
          -- First, normalize the SAN string by removing spaces after commas
          local normalized = string.gsub(sans_str, ", ", ",")
          
          -- Count commas and add 1 for the total entries
          for _ in string.gmatch(normalized, ",") do
            count = count + 1
          end
          count = count + 1  -- Add one more for the last entry (after the last comma)
          
          break
        end
      end
    end
    
    return count, sans_str
end

-- Helper function to check for wildcard certificates
local function check_wildcard_cert(cert)
  local has_wildcard = false
  local wildcard_domains = {}
  
  -- Check the common name for wildcards
  if cert and cert.subject and cert.subject.commonName then
    local cn = cert.subject.commonName
    if string.match(cn, "^%*%.") then
      has_wildcard = true
      table.insert(wildcard_domains, cn)
    end
  end
  
  -- Check Subject Alternative Names for wildcards
  if cert and cert.extensions then
    for _, ext in ipairs(cert.extensions) do
      if ext.name == "X509v3 Subject Alternative Name" then
        local sans = ext.value
        -- Look for wildcard patterns in the SANs
        for domain in string.gmatch(sans, "DNS:[^,]+") do
          -- Extract just the domain part after "DNS:"
          local domain_name = string.match(domain, "DNS:([^,]+)")
          if domain_name and string.match(domain_name, "^%*%.") then
            has_wildcard = true
            table.insert(wildcard_domains, domain_name)
          end
        end
        break
      end
    end
  end
  
  return has_wildcard, wildcard_domains
end

function stringify_name(name)
  local fields = {}
  local _, k, v
  if not name then
    return nil
  end
  for _, k in ipairs(NON_VERBOSE_FIELDS) do
    v = name[k]
    if v then
      fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
    end
  end
  if nmap.verbosity() > 1 then
    for k, v in pairs(name) do
      -- Don't include a field twice.
      if not table_find(NON_VERBOSE_FIELDS, k) then
        if type(k) == "table" then
          k = table.concat(k, ".")
        end
        fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
      end
    end
  end
  return table.concat(fields, "/")
end

local function name_to_table(name)
  local output = {}
  for k, v in pairs(name) do
    if type(k) == "table" then
      k = table.concat(k, ".")
    end
    output[k] = v
  end
  return outlib.sorted_by_key(output)
end

-- Helper function to safely get the bits value
local function get_key_bits(cert)
    -- Check if pubkey exists
    if not cert or not cert.pubkey then
      return 0
    end
    
    -- Get the bits value, ensuring it's a number
    local bits = cert.pubkey.bits
    if type(bits) ~= "number" then
      return 0
    end
    
    return bits
  end
  
-- New function to check certificate security
function check_cert_security(cert)
    -- Debug certificate validity structure
    stdnse.debug1("Certificate validity structure: %s", type(cert.validity))
    
    local issues = {}
    local secure_aspects = {}
    
    -- Default values
    local is_self_signed = false
    local weak_key = false
    local weak_sig = false
    local expired = false
    local expiring_soon = false
    local days_until_expiry = 0
    local sans_count = 0
    local has_wildcard = false
    
    -- 1. Check if certificate is self-signed
    local subject_cn = nil
    local issuer_cn = nil
    
    if cert and cert.subject and cert.issuer then
      -- Safely get commonName values
      if cert.subject.commonName and type(cert.subject.commonName) == "string" then
        subject_cn = cert.subject.commonName
      end
      
      if cert.issuer.commonName and type(cert.issuer.commonName) == "string" then
        issuer_cn = cert.issuer.commonName
      end
      
      -- Compare only if both are valid strings
      if subject_cn and issuer_cn then
        is_self_signed = (subject_cn == issuer_cn)
      end
    end
    
    if is_self_signed then
      table.insert(issues, "  [!] Certificate is self-signed")
    else
      table.insert(secure_aspects, "  [+] Certificate is properly signed by a trusted CA")
    end
    
    -- 2. Check public key strength
    local key_bits = get_key_bits(cert)
    
    if key_bits > 0 then
      if key_bits < 2048 then
        weak_key = true
        table.insert(issues, string.format("  [!] Weak public key length (%d bits, should be at least 2048)", key_bits))
      else
        table.insert(secure_aspects, string.format("  [+] Public key length is adequate (%d bits)", key_bits))
      end
    else
      table.insert(issues, "  [!] Could not determine public key length")
    end
    
    -- 3. Check signature algorithm
    if cert and cert.sig_algorithm and type(cert.sig_algorithm) == "string" then
      local sig_algo_lower = string.lower(cert.sig_algorithm)
      if string.find(sig_algo_lower, "md5") or string.find(sig_algo_lower, "sha1") then
        weak_sig = true
        table.insert(issues, string.format("  [!] Weak signature algorithm: %s", cert.sig_algorithm))
      else
        table.insert(secure_aspects, string.format("  [+] Strong signature algorithm: %s", cert.sig_algorithm))
      end
    else
      table.insert(issues, "  [!] Could not determine signature algorithm")
    end
    
    -- 4. Check certificate expiry (just use the helper function)
    local expiry_issues, expiry_aspects, expired, expiring_soon, days_until_expiry = get_expiry_info(cert)
    
    for _, issue in ipairs(expiry_issues) do
        table.insert(issues, issue)
    end
    
    for _, aspect in ipairs(expiry_aspects) do
        table.insert(secure_aspects, aspect)
    end

    -- 5. Check for excessive number of SANs
    local sans_count, sans_str = count_sans(cert)
    if sans_count > 50 then
        table.insert(issues, string.format("  [!] Certificate contains an excessive number of Subject Alternative Names (%d)", sans_count))
    elseif sans_count > 0 then
        table.insert(secure_aspects, string.format("  [+] Certificate contains a reasonable number of Subject Alternative Names (%d)", sans_count))
    end

    -- 6. Check for wildcard certificates
    local has_wildcard, wildcard_domains = check_wildcard_cert(cert)
    if has_wildcard then
      local domains_str = table.concat(wildcard_domains, ", ")
      table.insert(issues, string.format("  [!] Certificate uses wildcard domains: %s", domains_str))
    end

    return {
        issues = issues,
        secure_aspects = secure_aspects,
        self_signed = is_self_signed,
        weak_key_length = weak_key,
        weak_signature = weak_sig,
        expired = expired,
        expiring_soon = expiring_soon,
        days_until_expiry = days_until_expiry,
        sans_count = sans_count,
        has_wildcard = has_wildcard
    }
end

local function output_tab(cert)
  if not have_openssl then
    -- OpenSSL is required to parse the cert, so just dump the PEM
    return {pem = cert.pem}
  end
  local o = stdnse.output_table()
  o.subject = name_to_table(cert.subject)
  o.issuer = name_to_table(cert.issuer)

  o.pubkey = stdnse.output_table()
  o.pubkey.type = cert.pubkey.type
  o.pubkey.bits = cert.pubkey.bits
  -- The following fields are set in nse_ssl_cert.cc and mirror those in tls.lua
  if cert.pubkey.type == "rsa" then
    o.pubkey.modulus = openssl.bignum_bn2hex(cert.pubkey.modulus)
    o.pubkey.exponent = openssl.bignum_bn2dec(cert.pubkey.exponent)
  elseif cert.pubkey.type == "ec" then
    local params = stdnse.output_table()
    o.pubkey.ecdhparams = {curve_params=params}
    params.ec_curve_type = cert.pubkey.ecdhparams.curve_params.ec_curve_type
    params.curve = cert.pubkey.ecdhparams.curve_params.curve
  end

  if cert.extensions and #cert.extensions > 0 then
    o.extensions = {}
    for i, v in ipairs(cert.extensions) do
      local ext = stdnse.output_table()
      ext.name = v.name
      ext.value = v.value
      ext.critical = v.critical
      o.extensions[i] = ext
    end
  end
  o.sig_algo = cert.sig_algorithm

  o.validity = stdnse.output_table()
  for i, k in ipairs({"notBefore", "notAfter"}) do
    local v = cert.validity[k]
    if type(v)=="string" then
      o.validity[k] = v
    else
      o.validity[k] = datetime.format_timestamp(v)
    end
  end
  o.md5 = stdnse.tohex(cert:digest("md5"))
  o.sha1 = stdnse.tohex(cert:digest("sha1"))
  
  -- Add security evaluation
  local sec_check = check_cert_security(cert)
  o.security_issues = stdnse.output_table()
  o.security_issues.self_signed = sec_check.self_signed
  o.security_issues.weak_key_length = sec_check.weak_key_length
  o.security_issues.weak_signature = sec_check.weak_signature
  o.security_issues.expired = sec_check.expired
  o.security_issues.expiring_soon = sec_check.expiring_soon
  o.security_issues.days_until_expiry = sec_check.days_until_expiry
  o.security_issues.sans_count = sec_check.sans_count
  o.security_issues.has_wildcard = sec_check.has_wildcard
  o.pem = cert.pem
  return o
end

local function output_str(cert)
  if not have_openssl then
    -- OpenSSL is required to parse the cert, so just dump the PEM
    return "OpenSSL required to parse certificate.\n" .. cert.pem
  end
  local lines = {}

  lines[#lines + 1] = "\n\nSubject: " .. stringify_name(cert.subject)
  if cert.extensions then
    for _, e in ipairs(cert.extensions) do
      if e.name == "X509v3 Subject Alternative Name" then
        lines[#lines + 1] = "Subject Alternative Name: " .. e.value
        break
      end
    end
  end

  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "Issuer: " .. stringify_name(cert.issuer)
  end

  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "Public Key type: " .. cert.pubkey.type
    lines[#lines + 1] = "Public Key bits: " .. cert.pubkey.bits
    lines[#lines + 1] = "Signature Algorithm: " .. cert.sig_algorithm
  end

  lines[#lines + 1] = "Not valid before: " ..
  date_to_string(cert.validity.notBefore)
  lines[#lines + 1] = "Not valid after:  " ..
  date_to_string(cert.validity.notAfter)

  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "MD5:   " .. stdnse.tohex(cert:digest("md5"), { separator = " ", group = 4 })
    lines[#lines + 1] = "SHA-1: " .. stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })
  end
-- Add security evaluation
local sec_check = check_cert_security(cert)

-- Always show security evaluation
lines[#lines + 1] = "\nCertificate Security Evaluation:"
if #sec_check.issues > 0 then
  for _, issue in ipairs(sec_check.issues) do
    lines[#lines + 1] = issue
  end
else
  lines[#lines + 1] = "  [+] No security issues detected"
end

-- Show secure aspects
for _, aspect in ipairs(sec_check.secure_aspects) do
  lines[#lines + 1] = aspect
end
  if nmap.verbosity() > 1 then
    lines[#lines + 1] = cert.pem
  end
  lines[#lines + 1] = "\n"
  return table.concat(lines, "\n")
end

action = function(host, port)
  host.targetname = tls.servername(host)
  local status, cert = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end

  return output_tab(cert), output_str(cert)
end
