-- test case : --in-range=a --out-range=a --lua-desync=wgobfs:secret=mycoolpassword
-- encrypt standard wireguard messages - initiation, response, cookie - and change udp packet size
-- do not encrypt data messages and keepalives
-- wgobfs adds maximum of 30+padmax bytes to udp size
-- reduce MTU of wireguard interface to avoid ip fragmentation !
-- without knowing the secret encrypted packets should be crypto strong white noise with no signature
-- arg : secret - shared secret. any string. must be the same on both peers
-- arg : padmin - min random garbage bytes. 0 by default
-- arg : padmax - max random garbage bytes. 16 by default
-- NOTE : this function does not depend on zapret-lib.lua and should not be run under orchestrator (uses direct instance_cutoff)
function wgobfs(ctx, desync)
	if not desync.dis.udp then
		instance_cutoff_shim(ctx, desync)
		return
	end

	local padmin = desync.arg.padmin and tonumber(desync.arg.padmin) or 0
	local padmax = desync.arg.padmax and tonumber(desync.arg.padmax) or 16
	local function genkey()
		-- cache key in a global var bound to instance name
		local key_cache_name = desync.func_instance.."_key"
		local key = _G[key_cache_name]
		if not key then
			key = hkdf("sha256", "wgobfs_salt", desync.arg.secret, nil, 16)
			_G[key_cache_name] = key
		end
		return key
	end
	local function maybe_encrypted_payload(payload)
		for k,plsize in pairs({2+12+16+148, 2+12+16+92, 2+12+16+64}) do
			if #payload>=(plsize+padmin) and #payload<=(plsize+padmax) then
				return true
			end
		end
		return false
	end
	local function wg_payload_from_size(payload)
		if #payload==148 then return "wireguard_initiation"
		elseif #payload==92 then return "wireguard_response"
		elseif #payload==64 then return "wireguard_cookie"
		else return nil
		end
	end

	if not desync.arg.secret or #desync.arg.secret==0 then
		error("wgobfs: secret required")
	end
	if padmin>padmax then
		error("wgobfs: padmin>padmax")
	end
	if (desync.l7payload=="wireguard_initiation" or desync.l7payload=="wireguard_response" or desync.l7payload=="wireguard_cookie") and #desync.dis.payload<65506 then
		DLOG("wgobfs: encrypting '"..desync.l7payload.."'. size "..#desync.dis.payload)
		local key = genkey()
		-- in aes-gcm every message require it's own crypto secure random iv
		-- encrypting more than one message with the same iv is considered catastrophic failure
		-- iv must be sent with encrypted message
		local iv = bcryptorandom(12)
		local encrypted, atag = aes_gcm(true, key, iv, bu16(#desync.dis.payload)..desync.dis.payload..brandom(math.random(padmin,padmax)), nil)
		desync.dis.payload = iv..atag..encrypted
		return VERDICT_MODIFY
	end

	if desync.l7payload=="unknown" and maybe_encrypted_payload(desync.dis.payload) then
		local key = genkey()
		local iv = string.sub(desync.dis.payload,1,12)
		local atag = string.sub(desync.dis.payload,13,28)
		local decrypted, atag2 = aes_gcm(false, key, iv, string.sub(desync.dis.payload,29))
		if atag==atag2 then
			local plen = u16(decrypted)
			if plen>(#decrypted-2) then
				DLOG("wgobfs: bad decrypted payload data")
			else
				desync.dis.payload = string.sub(decrypted, 3, 3+plen-1)
				if b_debug then DLOG("wgobfs: decrypted '"..(wg_payload_from_size(desync.dis.payload) or "unknown").."' message. size "..plen) end
				return VERDICT_MODIFY
			end
		else
			DLOG("wgobfs: decrypt auth tag mismatch")
		end
	end
end

-- test case :
--  endpoint1:
--   --filter-icmp=0,8,128,129 --filter-ipp=193,198,209,250 --filter-tcp=* --filter-udp=* --in-range=a --lua-desync=ippxor:xor=192:dataxor=0xABCD
--   nft add rule inet ztest pre meta mark and 0x40000000 == 0 meta l4proto {193, 198, 209, 250} queue num 200 bypass
--   nft add rule inet ztest post meta mark and 0x40000000 == 0 tcp dport "{5001}" queue num 200 bypass
--   nft add rule inet ztest post meta mark and 0x40000000 == 0 udp dport "{5001}" queue num 200 bypass
--   iperf -i 1 -c endpoint2
--  endpoint2:
--   --filter-icmp=0,8,128,129 --filter-ipp=193,198,209,250 --filter-tcp=* --filter-udp=* --in-range=a --lua-desync=ippxor:xor=192:dataxor=0xABCD --server
--   nft add rule inet ztest pre meta mark and 0x40000000 == 0 meta l4proto {193, 198, 209, 250} queue num 200 bypass
--   nft add rule inet ztest post meta mark and 0x40000000 == 0 tcp sport "{5001}" queue num 200 bypass
--   nft add rule inet ztest post meta mark and 0x40000000 == 0 udp sport "{5001}" queue num 200 bypass
--   iperf -s
-- xor ip protocol number and optionally xor tcp,udp,icmp payload with supplied blob pattern
-- arg : ippxor - value to xor ip protocol number
-- arg : dataxor - blob to xor tcp, udp or icmp payload
-- arg : rebuild - always reconstruct desync.dis if after ippxor packet becomes tcp,udp or icmp
function ippxor(ctx, desync)
	local dataxor
	local function need_dxor(dis)
		return dataxor and dis.payload and #dis.payload>0 and (dis.tcp or dis.udp or dis.icmp)
	end
	local function dxor(dis)
		dis.payload = bxor(dis.payload, pattern(dataxor,1,#dis.payload))
	end

	if not desync.arg.ippxor then
		error("ippxor: ippxor value required")
	end
	local ippxor = tonumber(desync.arg.ippxor)
	if ippxor<0 or ippxor>0xFF then
		error("ippxor: invalid ippxor value. should be 0..255")
	end
	if desync.arg.dataxor then
		dataxor = blob(desync,desync.arg.dataxor)
		if #dataxor==0 then
			error("ippxor: empty dataxor value")
		end
	end

	local bdxor = need_dxor(desync.dis)
	if bdxor then
		DLOG("ippxor: dataxor size="..#desync.dis.payload)
		dxor(desync.dis)
	end

	local l3_from = ip_proto_l3(desync.dis)
	local l3_to = bitxor(l3_from, ippxor)
	DLOG("ippxor: "..l3_from.." => "..l3_to)
	fix_ip_proto(desync.dis, l3_to)

	if	(not bdxor and dataxor or desync.arg.rebuild) and
		(l3_to==IPPROTO_TCP and not desync.dis.tcp or
		l3_to==IPPROTO_UDP and not desync.dis.udp or
		l3_to==IPPROTO_ICMP and not (desync.dis.ip and desync.dis.icmp) or
		l3_to==IPPROTO_ICMPV6 and not (desync.dis.ip6 and desync.dis.icmp))
	then
		DLOG("ippxor: packet rebuild")
		local raw_ip = reconstruct_dissect(desync.dis, {ip6_preserve_next=true})
		local dis = dissect(raw_ip)
		if not dis.ip and not dis.ip6 then
			DLOG_ERR("ippxor: could not rebuild packet")
			return
		end
		desync.dis = dis
	end

	if not bdxor and need_dxor(desync.dis) then
		DLOG("ippxor: dataxor size="..#desync.dis.payload)
		dxor(desync.dis)
	end

	return VERDICT_MODIFY + VERDICT_PRESERVE_NEXT
end

-- test case:
--  endpoint1:
--   nfqws2 --lua-init=@/opt/zapret2/lua/zapret-obfs.lua --in-range=a --lua-desync=udp2icmp
--   nft add rule inet ztest2 post meta mark and 0x40000000 == 0 udp dport 12345 queue num 200 bypass
--   nft add rule inet ztest2 pre meta mark and 0x40000000 == 0 meta l4proto "{icmp,icmpv6}" queue num 200 bypass
--  endpoint2:
--   nfqws2 --lua-init=@/opt/zapret2/lua/zapret-obfs.lua --in-range=a --lua-desync=udp2icmp --server
--   nft add rule inet ztest2 post meta mark and 0x40000000 == 0 udp sport 12345 queue num 200 bypass
--   nft add rule inet ztest2 pre meta mark and 0x40000000 == 0 meta l4proto "{icmp,icmpv6}" queue num 200 bypass
-- packs udp datagram to icmp message without changing packet size
-- function keeps icmp identifier as (sport xor dport) to help traverse NAT (it won't help if NAT changes id)
-- one end must be in server mode, another - in client mode
-- arg : ctype - client icmp type
-- arg : ccode - client icmp code
-- arg : stype - server icmp type
-- arg : scode - server icmp code
-- arg : dataxor - blob to xor udp payload
-- arg : server=[0|1] - override server mode. by default use "--server" nfqws2 parameter
function udp2icmp(ctx, desync)
	local dataxor
	local bserver = desync.arg.server and (desync.arg.server~="0") or b_server

	local function one_byte_arg(name)
		if desync.arg[name] then
			local v = tonumber(desync.arg[name])
			if v<0 or v>0xFF then
				error("udp2icmp: invalid type or code value. should be 0..255")
			end
			return v
		end
	end
	local function ictype(send)
		local ctype = one_byte_arg("ctype")
		local stype = one_byte_arg("stype")
		if logical_xor(ctype,stype) then
			error("udp2icmp: ctype and stype must be both set or not set")
		end
		if not ctype then
			ctype = desync.dis.ip6 and ICMP6_ECHO_REQUEST or ICMP_ECHO
			stype = desync.dis.ip6 and ICMP6_ECHO_REPLY or ICMP_ECHOREPLY
		end
		return logical_xor(send,bserver) and ctype or stype
	end
	local function iccode(send)
		local ccode = one_byte_arg("ccode")
		local scode = one_byte_arg("scode")
		if logical_xor(ccode,scode) then
			error("udp2icmp: ccode and scode must be both set or not set")
		end
		if not ccode then
			ccode = 0
			scode = 0
		end
		return logical_xor(send,bserver) and ccode or scode
	end
	local function plxor()
		if dataxor then
			DLOG("udp2icmp: dataxor")
			desync.dis.payload = bxor(desync.dis.payload, pattern(dataxor,1,#desync.dis.payload))
		end
	end

	if desync.arg.dataxor then
		dataxor = blob(desync,desync.arg.dataxor)
		if #dataxor==0 then
			error("udp2icmp: empty dataxor value")
		end
	end

	if desync.dis.udp then
		plxor()
		if b_debug then -- save some cpu
			DLOG("udp2icmp: udp => icmp sport="..desync.dis.udp.uh_sport.." dport="..desync.dis.udp.uh_dport.." size="..#desync.dis.payload)
		end
		desync.dis.icmp = {
			icmp_type = ictype(true),
			icmp_code = iccode(true),
			icmp_data = u32(
				bu16(bitxor(desync.dis.udp.uh_sport,desync.dis.udp.uh_dport))..
				(bserver and bu16(desync.dis.udp.uh_sport) or bu16(desync.dis.udp.uh_dport)))
		}
		desync.dis.udp = nil
		fix_ip_proto(desync.dis)
		return VERDICT_MODIFY
	elseif desync.dis.icmp and desync.dis.icmp.icmp_type==ictype(false) and desync.dis.icmp.icmp_code==iccode(false) then
		local pl = bitand(desync.dis.icmp.icmp_data,0xFFFF)
		local pm = bitxor(bitrshift(desync.dis.icmp.icmp_data,16),pl)
		desync.dis.udp = {
			uh_sport = bserver and pm or pl,
			uh_dport = bserver and pl or pm,
			uh_ulen = UDP_BASE_LEN + #desync.dis.payload
		}
		desync.dis.icmp = nil
		fix_ip_proto(desync.dis)
		if b_debug then -- save some cpu
			DLOG("udp2icmp: icmp => udp sport="..desync.dis.udp.uh_sport.." dport="..desync.dis.udp.uh_dport.." size="..#desync.dis.payload)
		end
		plxor()
		return VERDICT_MODIFY
	end
end
