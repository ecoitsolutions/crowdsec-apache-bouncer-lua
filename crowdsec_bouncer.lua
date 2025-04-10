--[[
  crowdsec_bouncer.lua
  Copyright (C) 2025 <lucianlazar1983>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program. If not, see <https://www.gnu.org/licenses/>.

  Description:
  CrowdSec bouncer using mod_lua in Apache.
  - Reads config from /etc/crowdsec/bouncers/apache-bouncer.yaml
  - Checks each client IP via LAPI + cache
  - Logs actions to /var/log/crowdsec-apache-bouncer.log
]]

local lyaml = require("lyaml")
local socket = require("socket.http")
local cjson = require("cjson.safe")
local ltn12 = require("ltn12")

-- File paths
local config_file = "/etc/crowdsec/bouncers/apache-bouncer.yaml"
local log_file = "/var/log/crowdsec-apache-bouncer.log"

-- Logging function
local function log_message(level, msg)
    local f, err = io.open(log_file, "a")
    if f then
        -- Prepend level (INFO, WARN, ERROR) for better log readability
        f:write(os.date("%Y-%m-%d %H:%M:%S") .. " [" .. level .. "] " .. msg .. "\n")
        f:close()
    else
        -- If we cannot write to the log, print to Apache's error log as a fallback
        -- Use apache2.log_error if possible (requires Apache environment)
        -- This global function might be called before 'r' exists, so check needed.
        -- A simpler approach might be just to ignore log write errors silently,
        -- or attempt writing to stderr if not in Apache context.
        -- For now, ignoring write errors to prevent script failure.
        -- Consider adding Apache specific logging later if 'r' can be passed here.
    end
end

-- Read YAML configuration file
local function read_config(file)
    local f, err = io.open(file, "r")
    if not f then
        -- Use log_message which now includes level
        log_message("ERROR", "Cannot open config file '" .. file .. "': " .. (err or "unknown error"))
        return nil
    end
    local content = f:read("*all")
    f:close()
    -- Use pcall for safer YAML parsing
    local ok, cfg = pcall(lyaml.load, content)
    if not ok then
         log_message("ERROR", "Failed to parse YAML config file '".. file .."': ".. (cfg or "unknown error")) -- cfg will contain error message on failure
         return nil
    end
    return cfg
end

local cfg = read_config(config_file)
if not cfg then
    -- No valid config found, bouncer effectively disabled but will log error once.
    log_message("ERROR", "No valid config found or failed to load config, bouncer is disabled.")
    -- Bouncer will continue, but allow all traffic as API_KEY will be nil.
end

-- Use defaults if config loading failed or keys are missing
local LAPI_URL = (cfg and cfg["crowdsec_lapi_url"]) or "http://127.0.0.1:8080/"
local API_KEY = cfg and cfg["api_key"]
local CACHE_TTL = (cfg and tonumber(cfg["cache_ttl"])) or 60 -- Default 60 seconds

-- Normalize LAPI URL (remove trailing slash if present) and prepare endpoint
local DECISION_ENDPOINT = (LAPI_URL:gsub("/$", "") or "") .. "/v1/decisions?ip="
local cache = {} -- Simple in-memory cache { ip = { blocked = boolean, expires = timestamp } }

-- Function to check if an IP is blocked
local function isBlocked(ip)
    local now = os.time()
    local entry = cache[ip]
    if entry and entry.expires > now then
        -- Cache hit result
        log_message("INFO", "IP " .. ip .. " cache_hit="..tostring(entry.blocked))
        return entry.blocked
    end

    -- Query LAPI
    if not API_KEY or API_KEY == "PLACEHOLDER_API_KEY" then
        -- If we don't have a valid API key, we cannot block.
        log_message("WARN", "No valid API key configured, allowing IP " .. ip)
        return false
    end

    local req_url = DECISION_ENDPOINT .. ip
    local response_body = {}
    local req_success = false
    local resp_code = 0
    local blocked = false

    log_message("INFO", "Checking IP " .. ip .. " against LAPI " .. req_url)
    -- Use pcall for safer network requests
    local ok, res_or_err_code, res_headers, res_status = pcall(socket.request, {
        url = req_url,
        method = "GET",
        headers = {
            ["X-Api-Key"] = API_KEY,
            ["User-Agent"] = "crowdsec-apache-lua-bouncer/0.1" -- Add User-Agent
        },
        sink = ltn12.sink.table(response_body),
        timeout = 2 -- Set a reasonable timeout (e.g., 2 seconds)
    })

    if ok then
         -- socket.request returns: body_or_1, code, headers, status
         resp_code = res_or_err_code -- The second return value is the status code
         if resp_code == 200 then
             req_success = true
         end
    else
        -- pcall failed, res_or_err_code contains the error message
        log_message("ERROR", "LAPI request failed for IP " .. ip .. ". Error: " .. tostring(res_or_err_code))
        -- Fail open (allow) on network errors.
        return false
    end


    if req_success then
        local body_str = table.concat(response_body)
        -- Use pcall for safe JSON decoding
        local decode_ok, decoded = pcall(cjson.decode, body_str)

        if decode_ok and decoded and type(decoded) == "table" then
             -- Check if the response is null (no decisions) or an empty array
             if decoded ~= cjson.null and decoded.decisions and #decoded.decisions > 0 then
                 -- Check if there's at least one non-expired ban decision
                 for _, decision in ipairs(decoded.decisions) do
                      -- Basic check: If any ban decision exists, block.
                      -- Note: LAPI /v1/decisions endpoint should only return active decisions.
                      if decision.type:lower() == "ban" then
                         blocked = true
                         break -- Found a ban, no need to check further
                      end
                 end
             end -- else: null or empty decisions array means not blocked
        elseif not decode_ok then
             log_message("ERROR", "Failed to decode LAPI JSON response for IP " .. ip .. ". Error: " .. (decoded or "unknown") .. " Response body: ".. body_str)
             -- Fail open if JSON parsing fails
             blocked = false
        end
        log_message("INFO", "LAPI response for IP " .. ip .. ": blocked=" .. tostring(blocked))
    else
        -- Log non-200 responses if not already logged by pcall failure
        log_message("WARN", "LAPI request unsuccessful for IP " .. ip .. ", HTTP status code=" .. tostring(resp_code))
        -- Fail open: Allow if LAPI query fails or returns non-200
        blocked = false
    end

    -- Update cache regardless of LAPI success/failure to prevent hammering LAPI on errors
    cache[ip] = {
        blocked = blocked,
        expires = now + CACHE_TTL
    }

    return blocked
end

-- Apache hook function, receives the request object 'r'
function check_access(r)
    -- Get client IP address reliably
    local ip = r.useragent_ip
    if not ip then
        r.log_error("crowdsec_bouncer: Unable to determine client IP address.")
        return apache2.DECLINED -- Let other Apache modules handle it
    end

    if isBlocked(ip) then
        -- Use r.log_error for consistency with Apache logging if available
        r.log_error("crowdsec_bouncer: Blocking IP " .. ip .. " for request " .. r.the_request)
        log_message("INFO", "Blocking IP " .. ip .. " for request " .. r.the_request) -- Also log to dedicated file

        r.status = 403
        -- Set content type for the response body
        r.content_type = "text/html; charset=utf-8"
        r:write("<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Access Denied</h1>")
        r:write("<p>Your IP address has been blocked due to security policies.</p>")
        r:write("<p></p></body></html>\n")
        -- Return apache2.DONE to indicate the request handling is finished.
        return apache2.DONE
    else
        -- No need to log allowed IPs here, isBlocked function already logs cache hits/LAPI checks
        -- log_message("INFO", "Allowing IP " .. ip .. " for request " .. r.the_request) -- Optional: uncomment for very verbose logging
    end

    -- Return apache2.DECLINED to let Apache continue processing the request normally.
    return apache2.DECLINED
end