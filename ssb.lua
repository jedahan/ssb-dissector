-- [@micro](@wsoeSOhEE3yAIEF1gTVMeStUWnoejIz1P6a3lnvjaOM=.ed25519)'s very hacky ssb broadcast protocol decoder
-- cp ssb.lua ~/.config/wireshark/plugins/
local ssb_protocol = Proto("ssb", "Scuttlebutt");

local f_protocol = ProtoField.string("ssb.protocol")
local f_address = ProtoField.string("ssb.address")
local f_port = ProtoField.string("ssb.port")
local f_public_key = ProtoField.string("ssb.public_key")
local f_raw = ProtoField.string("ssb.raw")

ssb_protocol.fields = { f_protocol, f_address, f_port, f_public_key }

local data_dis = Dissector.get("data")

function string:split(sep)
   local sep, fields = sep or ";", {}
   local pattern = string.format("([^%s]+)", sep)
   self:gsub(pattern, function(c) fields[#fields+1] = c end)
   return fields
end

function ssb_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = ssb_protocol.name

    local addresses = buffer():string():split()

    for i, address in pairs(addresses) do
        local subtree = tree:add(ssb_protocol, "Scuttlebutt " .. address)
        local parts = address:split("://")
        local proto = parts[1]
        local ip = parts[2]
        local shs = parts[3]
        local publickey = parts[4]

        local port = parts[3]:split("~")[1]
        local length = 1
        length = length + proto:len()
        if string.find(address, "://") then length = length + 1 end

        subtree:add(f_address, buffer(length, ip:len()))
        length = length + ip:len() + 1

        subtree:add(f_port, buffer(length, port:len()))
        length = length + shs:len() + 1

        subtree:add(f_public_key, buffer(length, publickey:len()))

        length = length + shs:len() + 1
        subtree:add(f_raw, address)
    end
end

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(8008, ssb_protocol)
