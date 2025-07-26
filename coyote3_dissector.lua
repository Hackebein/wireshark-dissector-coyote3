-- ==== Post-dissector that triggers on ATT Value starting with Coyote cmd ====

-- bit ops (Wireshark Lua may expose bit32 instead of bit)
local bit = bit or bit32

local coyote_proto = Proto("coyote3", "DG-LAB Coyote 3.0")

-- ----- Fields (declare all first) -----
local f_raw    = ProtoField.bytes("coyote3.raw",   "Raw")

local f_cmd    = ProtoField.uint8 ("coyote3.cmd",  "Command", base.HEX)
local f_seq    = ProtoField.uint8 ("coyote3.seq",  "Sequence", base.DEC)

local f_mode_a = ProtoField.string("coyote3.mode_a", "Mode A")
local f_mode_b = ProtoField.string("coyote3.mode_b", "Mode B")
local f_set_a  = ProtoField.uint8 ("coyote3.set_a",  "Set Intensity A", base.DEC)
local f_set_b  = ProtoField.uint8 ("coyote3.set_b",  "Set Intensity B", base.DEC)

local f_a_seg  = ProtoField.string("coyote3.a_seg", "A Segments (f,int)")
local f_b_seg  = ProtoField.string("coyote3.b_seg", "B Segments (f,int)")

local f_soft_a = ProtoField.uint8 ("coyote3.soft_a", "Soft Limit A", base.DEC)
local f_soft_b = ProtoField.uint8 ("coyote3.soft_b", "Soft Limit B", base.DEC)
local f_fbal_a = ProtoField.uint8 ("coyote3.fbal_a", "Freq Balance A", base.DEC)
local f_fbal_b = ProtoField.uint8 ("coyote3.fbal_b", "Freq Balance B", base.DEC)
local f_wbal_a = ProtoField.uint8 ("coyote3.wbal_a", "Width Balance A", base.DEC)
local f_wbal_b = ProtoField.uint8 ("coyote3.wbal_b", "Width Balance B", base.DEC)

local f_cur_a  = ProtoField.uint8 ("coyote3.cur_a", "Current A", base.DEC)
local f_cur_b  = ProtoField.uint8 ("coyote3.cur_b", "Current B", base.DEC)

-- ----- SINGLE registration of fields (do this ONCE) -----
coyote_proto.fields = {
  f_raw, f_cmd, f_seq,
  f_mode_a, f_mode_b, f_set_a, f_set_b, f_a_seg, f_b_seg,
  f_soft_a, f_soft_b, f_fbal_a, f_fbal_b, f_wbal_a, f_wbal_b,
  f_cur_a, f_cur_b
}

-- ATT fields we need
local f_att_value  = Field.new("btatt.value")
-- local f_att_opcode = Field.new("btatt.opcode")  -- not used below; keep if needed

-- ----- helpers -----
local function mode_to_text(bits)
  if bits == 0 then return "No change"
  elseif bits == 1 then return "Relative +"
  elseif bits == 2 then return "Relative -"
  elseif bits == 3 then return "Absolute"
  else return "Unknown" end
end

local function add_summary_to_col(pinfo, label)
  local cur = tostring(pinfo.cols.info)
  if cur == "" then pinfo.cols.info = label else pinfo.cols.info = cur .. " | " .. label end
end

-- ----- decoders -----
local function decode_b0(buf, pinfo, tree)
  if buf:len() < 20 then
    local t = tree:add(coyote_proto, buf(), "Coyote3 B0 (Channel Data) [Malformed: <20 bytes]")
    t:add(f_raw, buf())
    return
  end
  local t = tree:add(coyote_proto, buf(), "Coyote3 B0 (Channel Data)")
  t:add(f_cmd, buf(0,1))

  local ctrl   = buf(1,1):uint()
  local seq    = bit.rshift(ctrl, 4)
  local mode_n = bit.band(ctrl, 0x0F)
  local modeA  = bit.rshift(mode_n, 2)
  local modeB  = bit.band(mode_n, 0x03)

  t:add(f_seq,    buf(1,1), seq)
  t:add(f_mode_a, buf(1,1), mode_to_text(modeA))
  t:add(f_mode_b, buf(1,1), mode_to_text(modeB))

  t:add(f_set_a,  buf(2,1))
  t:add(f_set_b,  buf(3,1))

  local a_desc = {}
  for i=0,3 do
    local f = buf(4+i,1):uint()
    local v = buf(8+i,1):uint()
    a_desc[#a_desc+1] = string.format("%d:(f=%d,int=%d)", i+1, f, v)
  end
  t:add(f_a_seg, buf(4,8), table.concat(a_desc, " "))

  local b_desc = {}
  for i=0,3 do
    local f = buf(12+i,1):uint()
    local v = buf(16+i,1):uint()
    b_desc[#b_desc+1] = string.format("%d:(f=%d,int=%d)", i+1, f, v)
  end
  t:add(f_b_seg, buf(12,8), table.concat(b_desc, " "))

  add_summary_to_col(pinfo, string.format("B0 seq=%d A=%d B=%d", seq, buf(2,1):uint(), buf(3,1):uint()))
end

local function decode_bf(buf, pinfo, tree)
  if buf:len() < 7 then
    local t = tree:add(coyote_proto, buf(), "Coyote3 BF (Setup Limits/Balances) [Malformed: <7 bytes]")
    t:add(f_raw, buf())
    return
  end
  local t = tree:add(coyote_proto, buf(), "Coyote3 BF (Setup Limits/Balances)")
  t:add(f_cmd,    buf(0,1))
  t:add(f_soft_a, buf(1,1))
  t:add(f_soft_b, buf(2,1))
  t:add(f_fbal_a, buf(3,1))
  t:add(f_fbal_b, buf(4,1))
  t:add(f_wbal_a, buf(5,1))
  t:add(f_wbal_b, buf(6,1))
  add_summary_to_col(pinfo, string.format("BF softA=%d softB=%d", buf(1,1):uint(), buf(2,1):uint()))
end

local function decode_b1(buf, pinfo, tree)
  if buf:len() < 4 then
    local t = tree:add(coyote_proto, buf(), "Coyote3 B1 (Intensity Update) [Malformed: <4 bytes]")
    t:add(f_raw, buf())
    return
  end
  local t = tree:add(coyote_proto, buf(), "Coyote3 B1 (Intensity Update)")
  t:add(f_cmd,   buf(0,1))
  t:add(f_seq,   buf(1,1))
  t:add(f_cur_a, buf(2,1))
  t:add(f_cur_b, buf(3,1))
  add_summary_to_col(pinfo, string.format("B1 seq=%d A=%d B=%d", buf(1,1):uint(), buf(2,1):uint(), buf(3,1):uint()))
end

local function decode_be(buf, pinfo, tree)
  local t = tree:add(coyote_proto, buf(), "Coyote3 BE (Deprecated/Unknown)")
  t:add(f_cmd, buf(0,1))
  if buf:len() > 1 then t:add(f_raw, buf(1, buf:len()-1)) end
  add_summary_to_col(pinfo, "BE")
end

local function dispatch_coyote(buf, pinfo, tree)
  local cmd = buf(0,1):uint()
  if     cmd == 0xB0 then decode_b0(buf, pinfo, tree)
  elseif cmd == 0xBF then decode_bf(buf, pinfo, tree)
  elseif cmd == 0xB1 then decode_b1(buf, pinfo, tree)
  elseif cmd == 0xBE then decode_be(buf, pinfo, tree)
  else
    local t = tree:add(coyote_proto, buf(), string.format("Coyote3 0x%02X (Unknown)", cmd))
    t:add(f_cmd, buf(0,1))
    if buf:len() > 1 then t:add(f_raw, buf(1, buf:len()-1)) end
  end
end

-- your existing detailed parsing, but written as a function taking a Tvb
local function dissect_coyote_value(buf, pinfo, tree)
  pinfo.cols.protocol = "Coyote3"
  dispatch_coyote(buf, pinfo, tree)
end

local coyote_post = Proto("coyote3_post", "DG-LAB Coyote 3.0 (post)")

function coyote_post.dissector(_, pinfo, tree)
  local v = f_att_value()
  if not v then return end
  local r = v.range
  if r:len() < 1 then return end

  local cmd = r:range(0,1):uint()
  if cmd ~= 0xB0 and cmd ~= 0xB1 and cmd ~= 0xBF and cmd ~= 0xBE then return end

  local buf = r:tvb("Coyote ATT Value")
  dissect_coyote_value(buf, pinfo, tree)
end

register_postdissector(coyote_post)
