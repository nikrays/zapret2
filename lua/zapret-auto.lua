-- arg: reqhost - require hostname, do not work with ip
function automate_host_record(desync)
	local key
	if desync.arg.reqhost then
		key = desync.track and desync.track.hostname
	else
		key = host_or_ip(desync)
	end
	if not key then
		DLOG("automate: host record key unavailable")
		return nil
	end
	DLOG("automate: host record key '"..key.."'")
	if not autostate then
		autostate = {}
	end
	if not autostate[key] then
		autostate[key] = {}
	end
	return autostate[key]
end
function automate_conn_record(desync)
	if not desync.track.lua_state.automate then
		desync.track.lua_state.automate = {}
	end
	return desync.track.lua_state.automate
end

-- counts failure, optionally (if crec is given) prevents dup failure counts in a single connection
-- if 'maxtime' between failures is exceeded then failure count is reset
-- return true if threshold ('fails') is reached
-- hres is host record. host or ip bound table
-- cres is connection record. connection bound table
function automate_failure_counter(hrec, crec, fails, maxtime)
	if crec and crec.failure then
		DLOG("automate: duplicate failure in the same connection. not counted")
	else
		if crec then crec.failure = true end
		local tnow=os.time()
		if not hrec.failure_time_last then
			hrec.failure_time_last = tnow
		end
		if not hrec.failure_counter then
			hrec.failure_counter = 0
		elseif tnow>(hrec.failure_time_last + maxtime) then
			DLOG("automate: failure counter reset because last failure was "..(tnow - hrec.failure_time_last).." seconds ago")
			hrec.failure_counter = 0
		end
		hrec.failure_counter = hrec.failure_counter + 1
		hrec.failure_time_last = tnow
		if b_debug then DLOG("automate: failure counter "..hrec.failure_counter..(fails and ('/'..fails) or '')) end
		if fails and hrec.failure_counter>=fails then
			hrec.failure_counter = nil -- reset counter
			return true
		end
	end
	return false
end

-- location is url compatible with Location: header
-- hostname is original hostname
function is_dpi_redirect(hostname, location)
	local ds = dissect_url(location)
	if ds.domain then
		local sld1 = dissect_nld(hostname,2)
		local sld2 = dissect_nld(ds.domain,2)
		return sld2 and sld1~=sld2
	end
	return false
end

-- standard failure detector
-- works with tcp and udp
-- detected failures:
--   incoming RST
--   incoming http redirection
--   outgoing retransmissions
--   udp too much out with too few in
-- arg: seq=<rseq> - tcp: if packet is beyond this relative sequence number treat this connection as successful. default is 64K
-- arg: retrans=N - tcp: retrans count threshold. default is 3
-- arg: rst=<rseq> - tcp: maximum relative sequence number to treat incoming RST as DPI reset. default is 1
-- arg: no_http_redirect - tcp: disable http_reply dpi redirect trigger
-- arg: udp_out - udp: >= outgoing udp packets. default is 3
-- arg: udp_in - udp: with <= incoming udp packets. default is 1
function standard_failure_detector(desync, crec, arg)
	if crec.nocheck then return false end

	local seq_rst = tonumber(arg.rst) or 1
	local retrans = tonumber(arg.retrans) or 3
	local maxseq = tonumber(arg.seq) or 0x10000
	local udp_in = tonumber(arg.udp_in) or 1
	local udp_out = tonumber(arg.udp_out) or 3

	local trigger = false
	if desync.dis.tcp then
		local seq = pos_get(desync,'s')
		if maxseq and seq>maxseq then
			DLOG("standard_failure_detector: s"..seq.." is beyond s"..maxseq..". treating connection as successful")
			crec.nocheck = true
			return false
		end

		if desync.outgoing then
			if #desync.dis.payload>0 and retrans and (crec.retrans or 0)<retrans then
				if is_retransmission(desync) then
					crec.retrans = crec.retrans and (crec.retrans+1) or 1
					DLOG("standard_failure_detector: retransmission "..crec.retrans.."/"..retrans)
					trigger = crec.retrans>=retrans
				end
			end
		else
			if seq_rst and bitand(desync.dis.tcp.th_flags, TH_RST)~=0 then
				trigger = seq<=seq_rst
				if b_debug then
					if trigger then
						DLOG("standard_failure_detector: incoming RST s"..seq.." in range s"..seq_rst)
					else
						DLOG("standard_failure_detector: not counting incoming RST s"..seq.." beyond s"..seq_rst)
					end
				end
			elseif not arg.no_http_redirect and desync.l7payload=="http_reply" and desync.track.hostname then
				local hdis = http_dissect_reply(desync.dis.payload)
				if hdis and (hdis.code==302 or hdis.code==307) and hdis.headers.location and hdis.headers.location then
					trigger = is_dpi_redirect(desync.track.hostname, hdis.headers.location.value)
					if b_debug then
						if trigger then
							DLOG("standard_failure_detector: http redirect "..hdis.code.." to '"..hdis.headers.location.value.."'. looks like DPI redirect.")
						else
							DLOG("standard_failure_detector: http redirect "..hdis.code.." to '"..hdis.headers.location.value.."'. NOT a DPI redirect.")
						end
					end
				end
			end
		end
	elseif desync.dis.udp then
		if desync.outgoing then
			if udp_out then
				local udp_in = udp_in or 0
				trigger = desync.track.pcounter_orig>=udp_out and desync.track.pcounter_reply<=udp_in
				if trigger then
					crec.nocheck = true
					if b_debug then
						DLOG("standard_failure_detector: udp_out "..desync.track.pcounter_orig..">="..udp_out.." udp_in "..desync.track.pcounter_reply.."<="..udp_in)
					end
				end
			end
		end
	end
	return trigger
end

-- circularily change strategy numbers when failure count reaches threshold ('fails')
-- works with tcp only
-- this orchestrator requires redirection of incoming traffic to cache RST and http replies !
-- each orchestrated instance must have strategy=N arg, where N starts from 1 and increment without gaps
-- if 'final' arg is present in an orchestrated instance it stops rotation
-- arg: fails=N - failture count threshold. default is 3
-- arg: time=<sec> - if last failure happened earlier than `maxtime` seconds ago - reset failure counter. default is 60.
-- arg: reqhost - pass with no tampering if hostname is unavailable
-- arg: detector - failure detector function name.
-- test case: nfqws2 --qnum 200 --debug --lua-init=@zapret-lib.lua --lua-init=@zapret-auto.lua --in-range=-s1 --lua-desync=circular --lua-desync=argdebug:strategy=1 --lua-desync=argdebug:strategy=2
function circular(ctx, desync)
	local function count_strategies(hrec, plan)
		if not hrec.ctstrategy then
			local uniq={}
			local n=0
			for i,instance in pairs(plan) do
				if instance.arg.strategy then
					n = tonumber(instance.arg.strategy)
					if not n or n<1 then
						error("circular: strategy number '"..tostring(instance.arg.strategy).."' is invalid")
					end
					uniq[tonumber(instance.arg.strategy)] = true
					if instance.arg.final then
						hrec.final = n
					end
				end
			end
			n=0
			for i,v in pairs(uniq) do
				n=n+1
			end
			if n~=#uniq then
				error("circular: strategies numbers must start from 1 and increment. gaps are not allowed.")
			end
			hrec.ctstrategy = n
		end
	end

	-- take over orchestration. prevent further instance execution in case of error
	execution_plan_cancel(ctx)

	if not desync.track then
		DLOG_ERR("circular: conntrack is missing but required")
		return
	end

	local plan = execution_plan(ctx)
	if #plan==0 then
		DLOG("circular: need some desync instances or useless")
		return
	end

	local hrec = automate_host_record(desync)
	if not hrec then
		DLOG("circular: passing with no tampering")
		return
	end

	count_strategies(hrec, plan)
	if hrec.ctstrategy==0 then
		error("circular: add strategy=N tag argument to each following instance ! N must start from 1 and increment")
	end

	if not hrec.nstrategy then
		DLOG("circular: start from strategy 1")
		hrec.nstrategy = 1
	end

	local verdict = VERDICT_PASS
	if hrec.final~=hrec.nstrategy then
		local crec = automate_conn_record(desync)
		local fails = tonumber(desync.arg.fails) or 3
		local maxtime = tonumber(desync.arg.time) or 60
		local failure_detector
		if desync.arg.detector then
			if type(_G[desync.arg.detector])~="function" then
				error("circular: invalid failure detector function '"..desync.arg.detector.."'")
			end
			failure_detector = _G[desync.arg.detector]
		else
			failure_detector = standard_failure_detector
		end
		if failure_detector(desync,crec,desync.arg) then
			-- failure happened. count failures.
			if automate_failure_counter(hrec, crec, fails, maxtime) then
				-- counter reaches threshold. circular strategy change
				hrec.nstrategy = (hrec.nstrategy % hrec.ctstrategy) + 1
				DLOG("circular: rotate strategy to "..hrec.nstrategy)
				if hrec.nstrategy == hrec.final then
					DLOG("circular: final strategy "..hrec.final.." reached. will rotate no more.")
				end
			end
		end
	end

	DLOG("circular: current strategy "..hrec.nstrategy)
	local dcopy = desync_copy(desync)
	for i=1,#plan do
		if plan[i].arg.strategy and tonumber(plan[i].arg.strategy)==hrec.nstrategy then
			verdict = plan_instance_execute(dcopy, verdict, plan[i])
		end
	end

	return verdict
end
