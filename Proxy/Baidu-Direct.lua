--[[
  author: 星璃
  email : StarColoredGlaze@outlook.com
  time  : 2023-06-18
  desc  : 百度直连，无任何干扰
]]--

local http = require 'http'
local backend = require 'backend'

local char = string.char
local byte = string.byte
local find = string.find
local sub = string.sub

local ADDRESS = backend.ADDRESS
local PROXY = backend.PROXY
local DIRECT_WRITE = backend.SUPPORT.DIRECT_WRITE

local SUCCESS = backend.RESULT.SUCCESS
local HANDSHAKE = backend.RESULT.HANDSHAKE
local DIRECT = backend.RESULT.DIRECT

local ctx_uuid = backend.get_uuid
local ctx_proxy_type = backend.get_proxy_type
local ctx_address_type = backend.get_address_type
local ctx_address_host = backend.get_address_host
local ctx_address_bytes = backend.get_address_bytes
local ctx_address_port = backend.get_address_port
local ctx_write = backend.write
local ctx_free = backend.free
local ctx_debug = backend.debug

local flags = {}
local kHttpHeaderSent = 1
local kHttpHeaderRecived = 2

local function createVerify(address)
  local index = 0
  for i = 1, #address do
    index = (index * 1318293 & 0x7FFFFFFF) + string.byte(address, i)
  end
  if index < 0 then
    index = index & 0x7FFFFFFF
  end
  -- ctx_debug('Host: ' .. address .. 'X-T5-Auth: ' ..index)
  local verify = 'X-T5-Auth: ' .. index .. '\r\n'
  return verify
end

function wa_lua_on_flags_cb(ctx)
    return DIRECT_WRITE
end

function wa_lua_on_handshake_cb(ctx)
    local uuid = ctx_uuid(ctx)

    if flags[uuid] == kHttpHeaderRecived then
        return true
    end

    if flags[uuid] ~= kHttpHeaderSent then
        local host = ctx_address_host(ctx)
        local port = ctx_address_port(ctx)
        local res = 'CONNECT ' .. host .. ':' .. port .. ' HTTP/1.1\r\n' ..
                    'Host: ' .. host .. ':' .. port .. '\r\n' ..
                    'Proxy-Connection: Keep-Alive\r\n'..
                    createVerify(host) .. '\r\n'
        ctx_write(ctx, res)
        flags[uuid] = kHttpHeaderSent
    end

    return false
end

function wa_lua_on_read_cb(ctx, buf)
    ctx_debug('wa_lua_on_read_cb')
    local uuid = ctx_uuid(ctx)
    if flags[uuid] == kHttpHeaderSent then
        flags[uuid] = kHttpHeaderRecived
        return HANDSHAKE, nil
    end
    return DIRECT, buf
end

function wa_lua_on_write_cb(ctx, buf)
    ctx_debug('wa_lua_on_write_cb')
    return DIRECT, buf
end

function wa_lua_on_close_cb(ctx)
    ctx_debug('wa_lua_on_close_cb')
    local uuid = ctx_uuid(ctx)
    flags[uuid] = nil
    ctx_free(ctx)
    return SUCCESS
end
