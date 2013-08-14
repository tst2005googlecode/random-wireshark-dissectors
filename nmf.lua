-- NMF wireshark decoder
-- NOTE THIS DISSECTOR ONLY WORK FOR 1-pass decoding!
-- I haven't spent the time making it work for 2-pass or N-pass encoding (i.e. Wireshark)

in_preamble = {}
encoding_types = {}
string_tables = {}

nmf_proto = Proto ("nmf",".NET Message Framing Protocol")

local f_recordtype = ProtoField.string("nmf.recordType", "RecordType")

nmf_proto.fields = {f_recordtype}

envelope_types = {}
envelope_types[6] = "Sized envelope"

nmf_record_types = {}
nmf_record_types[0] = "Version"
nmf_record_types[1] = "Mode"
nmf_record_types[2] = "Via"
nmf_record_types[3] = "Known encoding"
nmf_record_types[7] = "End"
nmf_record_types[11] = "Preamble ack"
nmf_record_types[12] = "Preamble end"

stream_ex = Field.new("tcp.stream")
stream_which = Field.new("tcp.srcport")

function nmf_proto.dissector (buf, pkt, root)
  pkt.cols.protocol = nmf_proto.name
  -- create subtree for nmf_proto
  subtree = root:add(nmf_proto, buf(0))
  -- add protocol fields to subtree
  local off = 0
  local is_in_pream = "true"
  local stream_key = tostring(stream_ex())
  if in_preamble[stream_key] then
    is_in_pream = in_preamble[stream_key]
  else
    in_preamble[stream_key] = "true"
  end
  while off < buf:len() do
    --print("In pream: "..tostring(is_in_pream)..", Record type: "..buf(off,1):uint().." offset: "..off)
    if buf(off,1):uint() == 6 then
      -- newsflash, not in preamble anymore
      is_in_pream = "false"
      in_preamble[stream_key] = "false"
    elseif is_in_pream == "false" then
      -- looks like a premable packet!
      is_in_pream = "true"
      in_preamble[stream_key] = "true"
    end
    if is_in_pream == "true" then
      subtree:add(f_recordtype, nmf_record_types[buf(off,1):uint()])
      pkt.private["doff"] = off+1    
      record_dissector_table:try(nmf_record_types[buf(off,1):uint()], buf:range(off+1):tvb(), pkt, subtree)
      if pkt.private["did_end_preamble"] ~= nil then
        in_preamble[stream_key] = "false"
        is_in_pream = "false"
      end
    else
      subtree:add(f_recordtype, envelope_types[buf(off,1):uint()])
      pkt.private["doff"] = off+1    
      envelope_dissector_table:try(envelope_types[buf(off,1):uint()], buf:range(off+1):tvb(), pkt, subtree)
      if pkt.desegment_len > 0 then
        return
      end
    end
    off = tonumber(pkt.private["doff"])
  end
end

tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(10000, nmf_proto)
tcp_dissector_table:add(808, nmf_proto)
record_dissector_table = DissectorTable.new("nmf.recordtype", "NMF_Records", ftypes.STRING)
envelope_dissector_table = DissectorTable.new("nmf.env_recordtype", "NMF_Envelopes", ftypes.STRING)
data_encoding_dissector_table = DissectorTable.new("nmf.data_encoding", "NMF_Data_encoding", ftypes.STRING)
binary_soap_dissector_table = DissectorTable.new("binary_soap.records", "Binary_SOAP_records", ftypes.STRING)

-- Version record, type=0
nmf_version_rec = Proto ("nmf_version_rec","NMF version")
local version = ProtoField.string("nmf.version.version", "Version")
nmf_version_rec.fields = {version}
function nmf_version_rec.dissector (buf, pkt, root)
  subtree:add(version, buf(0,1):uint().."."..buf(1,1):uint())
  pkt.private["doff"] = pkt.private["doff"]+2
end
record_dissector_table:add("Version", nmf_version_rec)

-- Mode record, type=1
mode_strings = {}
mode_strings[1]="Singleton-unsized"
mode_strings[2]="Duplex"
mode_strings[3]="Simplex"
mode_strings[4]="Singleton-sized"
nmf_mode_rec = Proto ("nmf_mode_rec","NMF mode")
local mode = ProtoField.uint8("nmf.mode.mode", "Mode", nil, mode_strings)
nmf_mode_rec.fields = {mode}
function nmf_mode_rec.dissector (buf, pkt, root)
  subtree:add(mode, buf(0,1))
  pkt.private["doff"] = pkt.private["doff"]+1
end
record_dissector_table:add("Mode", nmf_mode_rec)

function get_variable_length(buf, off)
  local b = 0
  local nb = buf(off,1):uint()
  --print("NEXT BYTE "..nb)
  off = off+1
  byte_cnt = 0
  while bit.band(nb,0x80) ~= 0 do
    b = bit.bor(b, bit.lshift(bit.band(nb, 0x7f), 7*byte_cnt))
    nb = buf(off,1):uint()
    --print("NEXT BYTE "..nb)
    off = off+1
    byte_cnt = byte_cnt+1
  end
  b = bit.bor(b, bit.lshift(bit.band(nb, 0x7f), 7*byte_cnt))
  return b, off
end

-- Via record, type=2
nmf_via_rec = Proto ("nmf_via_rec","NMF via")
local via_uri = ProtoField.string("nmf.via.uri", "URI")
nmf_via_rec.fields = {via_uri}
function nmf_via_rec.dissector (buf, pkt, root)
  local via_len, off = get_variable_length(buf, 0)
  subtree:add(via_uri, buf(off,via_len))
  pkt.private["doff"] = pkt.private["doff"]+off+via_len
end
record_dissector_table:add("Via", nmf_via_rec)

-- Known Encoding record, type=3
nmf_encoding_rec = Proto ("nmf_encoding_rec","NMF encoding")
encoding_strings = {}
encoding_strings[0]="UTF-8"
encoding_strings[1]="UTF-16"
encoding_strings[2]="Unicode LE"

encoding_strings[3]="UTF-8"
encoding_strings[4]="UTF-16"
encoding_strings[5]="Unicode LE"
encoding_strings[6]="MTOM"
encoding_strings[7]="Binary"
encoding_strings[8]="Binary w/in-band dictionary"

local encoding = ProtoField.uint8("nmf.encoding.encoding", "Encoding", nil, encoding_strings)
nmf_encoding_rec.fields = {encoding}
function nmf_encoding_rec.dissector (buf, pkt, root)
  subtree:add(encoding, buf(0,1))
  local stream_key = tostring(stream_ex())
  encoding_types[stream_key] = buf(0,1):uint()
  pkt.private["doff"] = pkt.private["doff"]+1
end
record_dissector_table:add("Known encoding", nmf_encoding_rec)

-- Preamble end record, type=12
nmf_pream_end_rec = Proto ("nmf_preamble_end","NMF preamble-end")
function nmf_pream_end_rec.dissector (buf, pkt, root)
end
record_dissector_table:add("Preamble end", nmf_pream_end_rec)

-- Preamble ack record, type=11
nmf_pream_ack_rec = Proto ("nmf_preamble_ack","NMF preamble-ack")
function nmf_pream_ack_rec.dissector (buf, pkt, root)
  pkt.private["did_end_preamble"] = true
end
record_dissector_table:add("Preamble ack", nmf_pream_ack_rec)

-- Sized envelope record, type=6
nmf_sz_envelope_rec = Proto ("nmf_sized_envelope","NMF sized envelope")
nmf_sz_envelope_rec.fields["desc"] = ProtoField.string("nmf_sz_envelope_rec.desc", "Description")
function nmf_sz_envelope_rec.dissector (buf, pkt, root)
  local payload_len, off = get_variable_length(buf, 0)
  root:add(nmf_sz_envelope_rec.fields["desc"], "Length "..payload_len, buf(0,off))
  local stream_key = tostring(stream_ex())
  local enc_type = encoding_types[stream_key]
  if enc_type == nil then
    enc_type = 8 -- truncated recording?
  end
  --print("Variable type "..encoding_strings[enc_type].." envelope: "..payload_len.." "..off)

  if payload_len > buf:len()-off then
    pkt.desegment_len = payload_len - (buf:len() - off)
    pkt.desegment_offset = 0
  else
    data_encoding_dissector_table:try(encoding_strings[enc_type], buf(off,payload_len):tvb(), pkt, root)
    pkt.private["doff"] = pkt.private["doff"]+off+payload_len
  end
end
envelope_dissector_table:add("Sized envelope", nmf_sz_envelope_rec)


-- Binary with in-band dictionary
bsoap_types = {}
bsoap_types[0x01] = "EndElement"
bsoap_types[0x06] = "ShortDictionaryAttribute"
bsoap_types[0x07] = "DictionaryAttribute"
bsoap_types[0x0a] = "ShortDictionaryXmlnsAttribute"
bsoap_types[0x0b] = "DictionaryXmlsAttribute"
bsoap_types[0x40] = "ShortElement"
bsoap_types[0x42] = "ShortDictionaryElement"
bsoap_types[0x43] = "DictionaryElement"
bsoap_types[0x82] = "OneText"
bsoap_types[0x83] = "OneText"
bsoap_types[0x84] = "FalseText"
bsoap_types[0x85] = "FalseText"

bsoap_types[0x86] = "TrueText"
bsoap_types[0x87] = "TrueText"
bsoap_types[0x88] = "Int8Text"
bsoap_types[0x89] = "Int8Text"
bsoap_types[0x8a] = "Int16Text"
bsoap_types[0x8b] = "Int16Text"

bsoap_types[0x96] = "DateTimeText"
bsoap_types[0x97] = "DateTimeText"
bsoap_types[0x98] = "Chars8Text"
bsoap_types[0x99] = "Chars8Text"
bsoap_types[0x9e] = "Bytes8Text"
bsoap_types[0x9f] = "Bytes8Text"
bsoap_types[0xa0] = "Bytes16Text"
bsoap_types[0xa1] = "Bytes16Text"
bsoap_types[0xaa] = "DictionaryText"
bsoap_types[0xab] = "DictionaryText"
bsoap_types[0xac] = "UniqueIdText"
bsoap_types[0xad] = "UniqueIdText"
bsoap_types[0xbc] = "QNameDictionaryTextRecord"
bsoap_types[0xbd] = "QNameDictionaryTextRecord"

is_attribute = {}
is_attribute["ShortDictionaryXmlnsAttribute"] = "true"
is_attribute["DictionaryXmlsAttribute"] = "true"
is_attribute["PrefixDictionaryAttribute"] = "true"
is_attribute["ShortDictionaryAttribute"] = "true"
is_attribute["DictionaryAttribute"] = "true"

binary_soap_rec = Proto ("binary_soap","Binary SOAP")
binary_soap_rec.fields["desc"] = ProtoField.string("binary_soap_rec.desc", "Description")
--binary_soap_rec.fields["type"] = ProtoField.string("binary_soap.recordType", "RecordType")
function binary_soap_rec.dissector (buf, pkt, root)
  pkt.cols.protocol = binary_soap_rec.name
  subtree = root:add(binary_soap_rec, buf(0))
  local off = 0
  pkt.private["bsoff"] = off
  pkt.private["most_recent_elem"] = ""
  binary_soap_dissector_table:try("StringTable", buf(off):tvb(), pkt, root)
  off = tonumber(pkt.private["bsoff"])
  while off < buf:len() do
    local rec_type_int = buf(off,1):uint()
    local rec_type = nil
    pkt.private["bsoff"] = off+1
    pkt.private["rec_type"] = rec_type_int
    if bsoap_types[rec_type_int] then
      rec_type = bsoap_types[rec_type_int]
    elseif rec_type_int >= 0x44 and rec_type_int <= 0x5d then
      pkt.private["prefix"] = string.char((rec_type_int-0x44)+string.byte("A",1))
      rec_type = "PrefixDictionaryElement"
    elseif rec_type_int >= 0x5e and rec_type_int <= 0x77 then
      pkt.private["prefix"] = string.char((rec_type_int-0x5e)+string.byte("A",1))
      rec_type = "PrefixDictionaryElement"
    elseif rec_type_int >= 0x0c and rec_type_int <= 0x25 then
      pkt.private["prefix"] = string.char((rec_type_int-0x0c)+string.byte("A",1))
      rec_type = "PrefixDictionaryAttribute"      
    elseif rec_type_int >= 0x26 and rec_type_int <= 0x3F then
      pkt.private["prefix"] = string.char((rec_type_int-0x26)+string.byte("A",1))
      rec_type = "PrefixAttribute"      
    else
      print("UNKNOWN Record type: "..rec_type_int.." off "..off)
      break
    end
    --print("Record type "..rec_type.."("..rec_type_int..") offset "..off)
    if rec_type then
      if pkt.private["expecting_attributes"] == "true" and not is_attribute[rec_type] and not pkt.private["expecting_text"] then
        root:add(binary_soap_rec.fields["desc"], ">")
        pkt.private["expecting_attributes"] = nil
      end
      binary_soap_dissector_table:try(rec_type, buf(off+1):tvb(), pkt, root)
    end
    off = tonumber(pkt.private["bsoff"])
  end
end
data_encoding_dissector_table:add("Binary w/in-band dictionary", binary_soap_rec)


predefined_dictionary_strings = {}
predefined_dictionary_strings[0x00]="mustUnderstand"
predefined_dictionary_strings[0x02]="Envelope"
predefined_dictionary_strings[0x04]="http://www.w3.org/2003/05/soap-envelope"
predefined_dictionary_strings[0x06]="http://www.w3.org/2005/08/addressing"
predefined_dictionary_strings[0x08]="Header"
predefined_dictionary_strings[0x0A]="Action"
predefined_dictionary_strings[0x0C]="To"
predefined_dictionary_strings[0x0E]="Body"
predefined_dictionary_strings[0x10]="Algorithm"
predefined_dictionary_strings[0x12]="RelatesTo"
predefined_dictionary_strings[0x14]="http://www.w3.org/2005/08/addressing/anonymous"
predefined_dictionary_strings[0x16]="URI"
predefined_dictionary_strings[0x18]="Reference"
predefined_dictionary_strings[0x1A]="MessageID"
predefined_dictionary_strings[0x1C]="Id"
predefined_dictionary_strings[0x1E]="Identifier"
predefined_dictionary_strings[0x20]="http://schemas.xmlsoap.org/ws/2005/02/rm"
predefined_dictionary_strings[0x22]="Transforms"
predefined_dictionary_strings[0x24]="Transform"
predefined_dictionary_strings[0x26]="DigestMethod"
predefined_dictionary_strings[0x28]="DigestValue"
predefined_dictionary_strings[0x2A]="Address"
predefined_dictionary_strings[0x2C]="ReplyTo"
predefined_dictionary_strings[0x2E]="SequenceAcknowledgement"
predefined_dictionary_strings[0x30]="AcknowledgementRange"
predefined_dictionary_strings[0x32]="Upper"
predefined_dictionary_strings[0x34]="Lower"
predefined_dictionary_strings[0x36]="BufferRemaining"
predefined_dictionary_strings[0x38]="http://schemas.microsoft.com/ws/2006/05/rm"
predefined_dictionary_strings[0x3A]="http://schemas.xmlsoap.org/ws/2005/02/rm/SequenceAcknowledgement"
predefined_dictionary_strings[0x3C]="SecurityTokenReference"
predefined_dictionary_strings[0x3E]="Sequence"
predefined_dictionary_strings[0x40]="MessageNumber"
predefined_dictionary_strings[0x42]="http://www.w3.org/2000/09/xmldsig#"
predefined_dictionary_strings[0x44]="http://www.w3.org/2000/09/xmldsig#enveloped-signature"
predefined_dictionary_strings[0x46]="KeyInfo"
predefined_dictionary_strings[0x48]="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
predefined_dictionary_strings[0x4A]="http://www.w3.org/2001/04/xmlenc#"
predefined_dictionary_strings[0x4C]="http://schemas.xmlsoap.org/ws/2005/02/sc"
predefined_dictionary_strings[0x4E]="DerivedKeyToken"
predefined_dictionary_strings[0x50]="Nonce"
predefined_dictionary_strings[0x52]="Signature"
predefined_dictionary_strings[0x54]="SignedInfo"
predefined_dictionary_strings[0x56]="CanonicalizationMethod"
predefined_dictionary_strings[0x58]="SignatureMethod"
predefined_dictionary_strings[0x5A]="SignatureValue "
predefined_dictionary_strings[0x5C]="DataReference "
predefined_dictionary_strings[0x5E]="EncryptedData "
predefined_dictionary_strings[0x60]="EncryptionMethod "
predefined_dictionary_strings[0x62]="CipherData"
predefined_dictionary_strings[0x64]="CipherValue"
predefined_dictionary_strings[0x66]="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
predefined_dictionary_strings[0x68]="Security"
predefined_dictionary_strings[0x6A]="Timestamp"
predefined_dictionary_strings[0x6C]="Created"
predefined_dictionary_strings[0x6E]="Expires"
predefined_dictionary_strings[0x70]="Length"
predefined_dictionary_strings[0x72]="ReferenceList"
predefined_dictionary_strings[0x74]="ValueType"
predefined_dictionary_strings[0x76]="Type"
predefined_dictionary_strings[0x78]="EncryptedHeader"
predefined_dictionary_strings[0x7A]="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"
predefined_dictionary_strings[0x7C]="RequestSecurityTokenResponseCollection"
predefined_dictionary_strings[0x7E]="http://schemas.xmlsoap.org/ws/2005/02/trust"
predefined_dictionary_strings[0x80]="http://schemas.xmlsoap.org/ws/2005/02/trust#BinarySecret"
predefined_dictionary_strings[0x82]="http://schemas.microsoft.com/ws/2006/02/transactions"
predefined_dictionary_strings[0x84]="s"
predefined_dictionary_strings[0x86]="Fault"
predefined_dictionary_strings[0x88]="MustUnderstand"
predefined_dictionary_strings[0x8A]="role"
predefined_dictionary_strings[0x8C]="relay"
predefined_dictionary_strings[0x8E]="Code"
predefined_dictionary_strings[0x90]="Reason"
predefined_dictionary_strings[0x92]="Text"
predefined_dictionary_strings[0x94]="Node"
predefined_dictionary_strings[0x96]="Role"
predefined_dictionary_strings[0x98]="Detail"
predefined_dictionary_strings[0x9A]="Value"
predefined_dictionary_strings[0x9C]="Subcode"
predefined_dictionary_strings[0x9E]="NotUnderstood"
predefined_dictionary_strings[0xA0]="qname"
predefined_dictionary_strings[0xA2]=""
predefined_dictionary_strings[0xA4]="From"
predefined_dictionary_strings[0xA6]="FaultTo"
predefined_dictionary_strings[0xA8]="EndpointReference"
predefined_dictionary_strings[0xAA]="PortType"
predefined_dictionary_strings[0xAC]="ServiceName"
predefined_dictionary_strings[0xAE]="PortName"
predefined_dictionary_strings[0xB0]="ReferenceProperties"
predefined_dictionary_strings[0xB2]="RelationshipType"
predefined_dictionary_strings[0xB4]="Reply"
predefined_dictionary_strings[0xB6]="a"
predefined_dictionary_strings[0xB8]="http://schemas.xmlsoap.org/ws/2006/02/addressingidentity"
predefined_dictionary_strings[0xBA]="Identity"
predefined_dictionary_strings[0xBC]="Spn"
predefined_dictionary_strings[0xBE]="Upn"
predefined_dictionary_strings[0xC0]="Rsa"
predefined_dictionary_strings[0xC2]="Dns"
predefined_dictionary_strings[0xC4]="X509v3Certificate"
predefined_dictionary_strings[0xC6]="http://www.w3.org/2005/08/addressing/fault"
predefined_dictionary_strings[0xC8]="ReferenceParameters"
predefined_dictionary_strings[0xCA]="IsReferenceParameter"
predefined_dictionary_strings[0xCC]="http://www.w3.org/2005/08/addressing/reply"
predefined_dictionary_strings[0xCE]="http://www.w3.org/2005/08/addressing/none"
predefined_dictionary_strings[0xD0]="Metadata"
predefined_dictionary_strings[0xD2]="http://schemas.xmlsoap.org/ws/2004/08/addressing"
predefined_dictionary_strings[0xD4]="http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
predefined_dictionary_strings[0xD6]="http://schemas.xmlsoap.org/ws/2004/08/addressing/fault"
predefined_dictionary_strings[0xD8]="http://schemas.xmlsoap.org/ws/2004/06/addressingex"
predefined_dictionary_strings[0xDA]="RedirectTo"
predefined_dictionary_strings[0xDC]="Via"
predefined_dictionary_strings[0xDE]="http://www.w3.org/2001/10/xml-exc-c14n#"
predefined_dictionary_strings[0xE0]="PrefixList"
predefined_dictionary_strings[0xE2]="InclusiveNamespaces"
predefined_dictionary_strings[0xE4]="ec"
predefined_dictionary_strings[0xE6]="SecurityContextToken"
predefined_dictionary_strings[0xE8]="Generation"
predefined_dictionary_strings[0xEA]="Label"
predefined_dictionary_strings[0xEC]="Offset"
predefined_dictionary_strings[0xEE]="Properties"
predefined_dictionary_strings[0xF0]="Cookie"
predefined_dictionary_strings[0xF2]="wsc"
predefined_dictionary_strings[0xF4]="http://schemas.xmlsoap.org/ws/2004/04/sc"
predefined_dictionary_strings[0xF6]="http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk"
predefined_dictionary_strings[0xF8]="http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct"
predefined_dictionary_strings[0xFA]="http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/SCT"
predefined_dictionary_strings[0xFC]="http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/SCT"
predefined_dictionary_strings[0xFE]="RenewNeeded"
predefined_dictionary_strings[0x100]="BadContextToken"
predefined_dictionary_strings[0x102]="c"
predefined_dictionary_strings[0x104]="http://schemas.xmlsoap.org/ws/2005/02/sc/dk"
predefined_dictionary_strings[0x106]="http://schemas.xmlsoap.org/ws/2005/02/sc/sct"
predefined_dictionary_strings[0x108]="http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT"
predefined_dictionary_strings[0x10A]="http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT"
predefined_dictionary_strings[0x10C]="http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Renew "
predefined_dictionary_strings[0x10E]="http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Renew "
predefined_dictionary_strings[0x110]="http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel "
predefined_dictionary_strings[0x112]="http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel "
predefined_dictionary_strings[0x114]="http://www.w3.org/2001/04/xmlenc#aes128-cbc"
predefined_dictionary_strings[0x116]="http://www.w3.org/2001/04/xmlenc#kw-aes128"
predefined_dictionary_strings[0x118]="http://www.w3.org/2001/04/xmlenc#aes192-cbc"
predefined_dictionary_strings[0x11A]="http://www.w3.org/2001/04/xmlenc#kw-aes192"
predefined_dictionary_strings[0x11C]="http://www.w3.org/2001/04/xmlenc#aes256-cbc"
predefined_dictionary_strings[0x11E]="http://www.w3.org/2001/04/xmlenc#kw-aes256"
predefined_dictionary_strings[0x120]="http://www.w3.org/2001/04/xmlenc#des-cbc"
predefined_dictionary_strings[0x122]="http://www.w3.org/2000/09/xmldsig#dsa-sha1"
predefined_dictionary_strings[0x124]="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
predefined_dictionary_strings[0x126]="http://www.w3.org/2000/09/xmldsig#hmac-sha1"
predefined_dictionary_strings[0x128]="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
predefined_dictionary_strings[0x12A]="http://schemas.xmlsoap.org/ws/2005/02/sc/dk/p_sha1"
predefined_dictionary_strings[0x12C]="http://www.w3.org/2001/04/xmlenc#ripemd160"
predefined_dictionary_strings[0x12E]="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
predefined_dictionary_strings[0x130]="http://www.w3.org/2000/09/xmldsig#rsa-sha1"
predefined_dictionary_strings[0x132]="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
predefined_dictionary_strings[0x134]="http://www.w3.org/2001/04/xmlenc#rsa-1_5"
predefined_dictionary_strings[0x136]="http://www.w3.org/2000/09/xmldsig#sha1"
predefined_dictionary_strings[0x138]="http://www.w3.org/2001/04/xmlenc#sha256"
predefined_dictionary_strings[0x13A]="http://www.w3.org/2001/04/xmlenc#sha512"
predefined_dictionary_strings[0x13C]="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
predefined_dictionary_strings[0x13E]="http://www.w3.org/2001/04/xmlenc#kw-tripledes"
predefined_dictionary_strings[0x140]="http://schemas.xmlsoap.org/2005/02/trust/tlsnego#TLS_Wrap"
predefined_dictionary_strings[0x142]="http://schemas.xmlsoap.org/2005/02/trust/spnego#GSS_Wrap"
predefined_dictionary_strings[0x144]="http://schemas.microsoft.com/ws/2006/05/security"
predefined_dictionary_strings[0x146]="dnse"
predefined_dictionary_strings[0x148]="o"
predefined_dictionary_strings[0x14A]="Password"
predefined_dictionary_strings[0x14C]="PasswordText"
predefined_dictionary_strings[0x14E]="Username"
predefined_dictionary_strings[0x150]="UsernameToken"
predefined_dictionary_strings[0x152]="BinarySecurityToken"
predefined_dictionary_strings[0x154]="EncodingType"
predefined_dictionary_strings[0x156]="KeyIdentifier"
predefined_dictionary_strings[0x158]="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security- 1.0#Base64Binary"
predefined_dictionary_strings[0x15A]="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security- 1.0#HexBinary"
predefined_dictionary_strings[0x15C]="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Text"
predefined_dictionary_strings[0x15E]="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile- 1.0#X509SubjectKeyIdentifier"
predefined_dictionary_strings[0x160]="http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ"
predefined_dictionary_strings[0x162]="http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile- 1.1#GSS_Kerberosv5_AP_REQ1510"
predefined_dictionary_strings[0x164]="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID"
predefined_dictionary_strings[0x166]="Assertion"
predefined_dictionary_strings[0x168]="urn:oasis:names:tc:SAML:1.0:assertion"
predefined_dictionary_strings[0x16A]="http://docs.oasis-open.org/wss/oasis-wss-rel-token-profile-1.0.pdf#license"
predefined_dictionary_strings[0x16C]="FailedAuthentication"
predefined_dictionary_strings[0x16E]="InvalidSecurityToken"
predefined_dictionary_strings[0x170]="InvalidSecurity"
predefined_dictionary_strings[0x172]="k"
predefined_dictionary_strings[0x174]="SignatureConfirmation"
predefined_dictionary_strings[0x176]="TokenType"
predefined_dictionary_strings[0x178]="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1"
predefined_dictionary_strings[0x17A]="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey"
predefined_dictionary_strings[0x17C]="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1"
predefined_dictionary_strings[0x17E]="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"
predefined_dictionary_strings[0x180]="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
predefined_dictionary_strings[0x182]="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID"
predefined_dictionary_strings[0x184]="AUTH-HASH"
predefined_dictionary_strings[0x186]="RequestSecurityTokenResponse "
predefined_dictionary_strings[0x188]="KeySize"
predefined_dictionary_strings[0x18A]="RequestedTokenReference"
predefined_dictionary_strings[0x18C]="AppliesTo"
predefined_dictionary_strings[0x18E]="Authenticator"
predefined_dictionary_strings[0x190]="CombinedHash"
predefined_dictionary_strings[0x192]="BinaryExchange"
predefined_dictionary_strings[0x194]="Lifetime"
predefined_dictionary_strings[0x196]="RequestedSecurityToken"
predefined_dictionary_strings[0x198]="Entropy"
predefined_dictionary_strings[0x19A]="RequestedProofToken"
predefined_dictionary_strings[0x19C]="ComputedKey"
predefined_dictionary_strings[0x19E]="RequestSecurityToken"
predefined_dictionary_strings[0x1A0]="RequestType"
predefined_dictionary_strings[0x1A2]="Context"
predefined_dictionary_strings[0x1A4]="BinarySecret"
predefined_dictionary_strings[0x1A6]="http://schemas.xmlsoap.org/ws/2005/02/trust/spnego"
predefined_dictionary_strings[0x1A8]="http://schemas.xmlsoap.org/ws/2005/02/trust/tlsnego"
predefined_dictionary_strings[0x1AA]="wst"
predefined_dictionary_strings[0x1AC]="http://schemas.xmlsoap.org/ws/2004/04/trust"
predefined_dictionary_strings[0x1AE]="http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue"
predefined_dictionary_strings[0x1B0]="http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Issue"
predefined_dictionary_strings[0x1B2]="http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue"
predefined_dictionary_strings[0x1B4]="http://schemas.xmlsoap.org/ws/2004/04/security/trust/CK/PSHA1"
predefined_dictionary_strings[0x1B6]="http://schemas.xmlsoap.org/ws/2004/04/security/trust/SymmetricKey"
predefined_dictionary_strings[0x1B8]="http://schemas.xmlsoap.org/ws/2004/04/security/trust/Nonce"
predefined_dictionary_strings[0x1BA]="KeyType"
predefined_dictionary_strings[0x1BC]="http://schemas.xmlsoap.org/ws/2004/04/trust/SymmetricKey"
predefined_dictionary_strings[0x1BE]="http://schemas.xmlsoap.org/ws/2004/04/trust/PublicKey"
predefined_dictionary_strings[0x1C0]="Claims"
predefined_dictionary_strings[0x1C2]="InvalidRequest"
predefined_dictionary_strings[0x1C4]="RequestFailed"
predefined_dictionary_strings[0x1C6]="SignWith"
predefined_dictionary_strings[0x1C8]="EncryptWith"
predefined_dictionary_strings[0x1CA]="EncryptionAlgorithm"
predefined_dictionary_strings[0x1CC]="CanonicalizationAlgorithm"
predefined_dictionary_strings[0x1CE]="ComputedKeyAlgorithm"
predefined_dictionary_strings[0x1D0]="UseKey"
predefined_dictionary_strings[0x1D2]="http://schemas.microsoft.com/net/2004/07/secext/WS-SPNego"
predefined_dictionary_strings[0x1D4]="http://schemas.microsoft.com/net/2004/07/secext/TLSNego"
predefined_dictionary_strings[0x1D6]="t"
predefined_dictionary_strings[0x1D8]="http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"
predefined_dictionary_strings[0x1DA]="http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue"
predefined_dictionary_strings[0x1DC]="http://schemas.xmlsoap.org/ws/2005/02/trust/Issue"
predefined_dictionary_strings[0x1DE]="http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey"
predefined_dictionary_strings[0x1E0]="http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1"
predefined_dictionary_strings[0x1E2]="http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce"
predefined_dictionary_strings[0x1E4]="RenewTarget"
predefined_dictionary_strings[0x1E6]="CancelTarget"
predefined_dictionary_strings[0x1E8]="RequestedTokenCancelled"
predefined_dictionary_strings[0x1EA]="RequestedAttachedReference"
predefined_dictionary_strings[0x1EC]="RequestedUnattachedReference"
predefined_dictionary_strings[0x1EE]="IssuedTokens"
predefined_dictionary_strings[0x1F0]="http://schemas.xmlsoap.org/ws/2005/02/trust/Renew"
predefined_dictionary_strings[0x1F2]="http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel"
predefined_dictionary_strings[0x1F4]="http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey"
predefined_dictionary_strings[0x1F6]="Access"
predefined_dictionary_strings[0x1F8]="AccessDecision"
predefined_dictionary_strings[0x1FA]="Advice"
predefined_dictionary_strings[0x1FC]="AssertionID"
predefined_dictionary_strings[0x1FE]="AssertionIDReference"
predefined_dictionary_strings[0x200]="Attribute"
predefined_dictionary_strings[0x202]="AttributeName"
predefined_dictionary_strings[0x204]="AttributeNamespace"
predefined_dictionary_strings[0x206]="AttributeStatement"
predefined_dictionary_strings[0x208]="AttributeValue"
predefined_dictionary_strings[0x20A]="Audience"
predefined_dictionary_strings[0x20C]="AudienceRestrictionCondition"
predefined_dictionary_strings[0x20E]="AuthenticationInstant"
predefined_dictionary_strings[0x210]="AuthenticationMethod"
predefined_dictionary_strings[0x212]="AuthenticationStatement"
predefined_dictionary_strings[0x214]="AuthorityBinding"
predefined_dictionary_strings[0x216]="AuthorityKind"
predefined_dictionary_strings[0x218]="AuthorizationDecisionStatement"
predefined_dictionary_strings[0x21A]="Binding"
predefined_dictionary_strings[0x21C]="Condition"
predefined_dictionary_strings[0x21E]="Conditions"
predefined_dictionary_strings[0x220]="Decision"
predefined_dictionary_strings[0x222]="DoNotCacheCondition"
predefined_dictionary_strings[0x224]="Evidence"
predefined_dictionary_strings[0x226]="IssueInstant"
predefined_dictionary_strings[0x228]="Issuer"
predefined_dictionary_strings[0x22A]="Location"
predefined_dictionary_strings[0x22C]="MajorVersion"
predefined_dictionary_strings[0x22E]="MinorVersion"
predefined_dictionary_strings[0x230]="NameIdentifier"
predefined_dictionary_strings[0x232]="Format"
predefined_dictionary_strings[0x234]="NameQualifier"
predefined_dictionary_strings[0x236]="Namespace"
predefined_dictionary_strings[0x238]="NotBefore"
predefined_dictionary_strings[0x23A]="NotOnOrAfter"
predefined_dictionary_strings[0x23C]="saml"
predefined_dictionary_strings[0x23E]="Statement"
predefined_dictionary_strings[0x240]="Subject"
predefined_dictionary_strings[0x242]="SubjectConfirmation"
predefined_dictionary_strings[0x244]="SubjectConfirmationData"
predefined_dictionary_strings[0x246]="ConfirmationMethod"
predefined_dictionary_strings[0x248]="urn:oasis:names:tc:SAML:1.0:cm:holder-of-key"
predefined_dictionary_strings[0x24A]="urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"
predefined_dictionary_strings[0x24C]="SubjectLocality"
predefined_dictionary_strings[0x24E]="DNSAddress"
predefined_dictionary_strings[0x250]="IPAddress"
predefined_dictionary_strings[0x252]="SubjectStatement"
predefined_dictionary_strings[0x254]="urn:oasis:names:tc:SAML:1.0:am:unspecified"
predefined_dictionary_strings[0x256]="xmlns"
predefined_dictionary_strings[0x258]="Resource"
predefined_dictionary_strings[0x25A]="UserName"
predefined_dictionary_strings[0x25C]="urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
predefined_dictionary_strings[0x25E]="EmailName"
predefined_dictionary_strings[0x260]="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
predefined_dictionary_strings[0x262]="u"
predefined_dictionary_strings[0x264]="ChannelInstance"
predefined_dictionary_strings[0x266]="http://schemas.microsoft.com/ws/2005/02/duplex"
predefined_dictionary_strings[0x268]="Encoding"
predefined_dictionary_strings[0x26A]="MimeType"
predefined_dictionary_strings[0x26C]="CarriedKeyName"
predefined_dictionary_strings[0x26E]="Recipient"
predefined_dictionary_strings[0x270]="EncryptedKey"
predefined_dictionary_strings[0x272]="KeyReference"
predefined_dictionary_strings[0x274]="e"
predefined_dictionary_strings[0x276]="http://www.w3.org/2001/04/xmlenc#Element"
predefined_dictionary_strings[0x278]="http://www.w3.org/2001/04/xmlenc#Content"
predefined_dictionary_strings[0x27A]="KeyName"
predefined_dictionary_strings[0x27C]="MgmtData"
predefined_dictionary_strings[0x27E]="KeyValue"
predefined_dictionary_strings[0x280]="RSAKeyValue"
predefined_dictionary_strings[0x282]="Modulus"
predefined_dictionary_strings[0x284]="Exponent"
predefined_dictionary_strings[0x286]="X509Data"
predefined_dictionary_strings[0x288]="X509IssuerSerial"
predefined_dictionary_strings[0x28A]="X509IssuerName"
predefined_dictionary_strings[0x28C]="X509SerialNumber"
predefined_dictionary_strings[0x28E]="X509Certificate"
predefined_dictionary_strings[0x290]="AckRequested"
predefined_dictionary_strings[0x292]="http://schemas.xmlsoap.org/ws/2005/02/rm/AckRequested"
predefined_dictionary_strings[0x294]="AcksTo"
predefined_dictionary_strings[0x296]="Accept"
predefined_dictionary_strings[0x298]="CreateSequence"
predefined_dictionary_strings[0x29A]="http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence"
predefined_dictionary_strings[0x29C]="CreateSequenceRefused"
predefined_dictionary_strings[0x29E]="CreateSequenceResponse"
predefined_dictionary_strings[0x2A0]="http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequenceResponse"
predefined_dictionary_strings[0x2A2]="FaultCode"
predefined_dictionary_strings[0x2A4]="InvalidAcknowledgement"
predefined_dictionary_strings[0x2A6]="LastMessage"
predefined_dictionary_strings[0x2A8]="http://schemas.xmlsoap.org/ws/2005/02/rm/LastMessage"
predefined_dictionary_strings[0x2AA]="LastMessageNumberExceeded"
predefined_dictionary_strings[0x2AC]="MessageNumberRollover"
predefined_dictionary_strings[0x2AE]="Nack"
predefined_dictionary_strings[0x2B0]="netrm"
predefined_dictionary_strings[0x2B2]="Offer"
predefined_dictionary_strings[0x2B4]="r"
predefined_dictionary_strings[0x2B6]="SequenceFault"
predefined_dictionary_strings[0x2B8]="SequenceTerminated"
predefined_dictionary_strings[0x2BA]="TerminateSequence"
predefined_dictionary_strings[0x2BC]="http://schemas.xmlsoap.org/ws/2005/02/rm/TerminateSequence"
predefined_dictionary_strings[0x2BE]="UnknownSequence"
predefined_dictionary_strings[0x2C0]="http://schemas.microsoft.com/ws/2006/02/tx/oletx"
predefined_dictionary_strings[0x2C2]="oletx"
predefined_dictionary_strings[0x2C4]="OleTxTransaction"
predefined_dictionary_strings[0x2C6]="PropagationToken"
predefined_dictionary_strings[0x2C8]="http://schemas.xmlsoap.org/ws/2004/10/wscoor"
predefined_dictionary_strings[0x2CA]="wscoor"
predefined_dictionary_strings[0x2CC]="CreateCoordinationContext"
predefined_dictionary_strings[0x2CE]="CreateCoordinationContextResponse"
predefined_dictionary_strings[0x2D0]="CoordinationContext"
predefined_dictionary_strings[0x2D2]="CurrentContext"
predefined_dictionary_strings[0x2D4]="CoordinationType"
predefined_dictionary_strings[0x2D6]="RegistrationService"
predefined_dictionary_strings[0x2D8]="Register"
predefined_dictionary_strings[0x2DA]="RegisterResponse"
predefined_dictionary_strings[0x2DC]="ProtocolIdentifier"
predefined_dictionary_strings[0x2DE]="CoordinatorProtocolService"
predefined_dictionary_strings[0x2E0]="ParticipantProtocolService"
predefined_dictionary_strings[0x2E2]="http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContext"
predefined_dictionary_strings[0x2E4]="http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContextResponse"
predefined_dictionary_strings[0x2E6]="http://schemas.xmlsoap.org/ws/2004/10/wscoor/Register"
predefined_dictionary_strings[0x2E8]="http://schemas.xmlsoap.org/ws/2004/10/wscoor/RegisterResponse"
predefined_dictionary_strings[0x2EA]="http://schemas.xmlsoap.org/ws/2004/10/wscoor/fault"
predefined_dictionary_strings[0x2EC]="ActivationCoordinatorPortType"
predefined_dictionary_strings[0x2EE]="RegistrationCoordinatorPortType"
predefined_dictionary_strings[0x2F0]="InvalidState"
predefined_dictionary_strings[0x2F2]="InvalidProtocol"
predefined_dictionary_strings[0x2F4]="InvalidParameters"
predefined_dictionary_strings[0x2F6]="NoActivity"
predefined_dictionary_strings[0x2F8]="ContextRefused"
predefined_dictionary_strings[0x2FA]="AlreadyRegistered"
predefined_dictionary_strings[0x2FC]="http://schemas.xmlsoap.org/ws/2004/10/wsat"
predefined_dictionary_strings[0x2FE]="wsat"
predefined_dictionary_strings[0x300]="http://schemas.xmlsoap.org/ws/2004/10/wsat/Completion"
predefined_dictionary_strings[0x302]="http://schemas.xmlsoap.org/ws/2004/10/wsat/Durable2PC"
predefined_dictionary_strings[0x304]="http://schemas.xmlsoap.org/ws/2004/10/wsat/Volatile2PC"
predefined_dictionary_strings[0x306]="Prepare"
predefined_dictionary_strings[0x308]="Prepared"
predefined_dictionary_strings[0x30A]="ReadOnly"
predefined_dictionary_strings[0x30C]="Commit"
predefined_dictionary_strings[0x30E]="Rollback"
predefined_dictionary_strings[0x310]="Committed"
predefined_dictionary_strings[0x312]="Aborted"
predefined_dictionary_strings[0x314]="Replay"
predefined_dictionary_strings[0x316]="http://schemas.xmlsoap.org/ws/2004/10/wsat/Commit"
predefined_dictionary_strings[0x318]="http://schemas.xmlsoap.org/ws/2004/10/wsat/Rollback"
predefined_dictionary_strings[0x31A]="http://schemas.xmlsoap.org/ws/2004/10/wsat/Committed"
predefined_dictionary_strings[0x31C]="http://schemas.xmlsoap.org/ws/2004/10/wsat/Aborted"
predefined_dictionary_strings[0x31E]="http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepare"
predefined_dictionary_strings[0x320]="http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepared"
predefined_dictionary_strings[0x322]="http://schemas.xmlsoap.org/ws/2004/10/wsat/ReadOnly"
predefined_dictionary_strings[0x324]="http://schemas.xmlsoap.org/ws/2004/10/wsat/Replay"
predefined_dictionary_strings[0x326]="http://schemas.xmlsoap.org/ws/2004/10/wsat/fault"
predefined_dictionary_strings[0x328]="CompletionCoordinatorPortType"
predefined_dictionary_strings[0x32A]="CompletionParticipantPortType"
predefined_dictionary_strings[0x32C]="CoordinatorPortType"
predefined_dictionary_strings[0x32E]="ParticipantPortType"
predefined_dictionary_strings[0x330]="InconsistentInternalState"
predefined_dictionary_strings[0x332]="mstx"
predefined_dictionary_strings[0x334]="Enlistment"
predefined_dictionary_strings[0x336]="protocol"
predefined_dictionary_strings[0x338]="LocalTransactionId"
predefined_dictionary_strings[0x33A]="IsolationLevel"
predefined_dictionary_strings[0x33C]="IsolationFlags"
predefined_dictionary_strings[0x33E]="Description"
predefined_dictionary_strings[0x340]="Loopback"
predefined_dictionary_strings[0x342]="RegisterInfo"
predefined_dictionary_strings[0x344]="ContextId"
predefined_dictionary_strings[0x346]="TokenId"
predefined_dictionary_strings[0x348]="AccessDenied"
predefined_dictionary_strings[0x34A]="InvalidPolicy"
predefined_dictionary_strings[0x34C]="CoordinatorRegistrationFailed"
predefined_dictionary_strings[0x34E]="TooManyEnlistments"
predefined_dictionary_strings[0x350]="Disabled"
predefined_dictionary_strings[0x352]="ActivityId"
predefined_dictionary_strings[0x354]="http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics"
predefined_dictionary_strings[0x356]="http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5APREQSHA1"
predefined_dictionary_strings[0x358]="http://schemas.xmlsoap.org/ws/2002/12/policy"
predefined_dictionary_strings[0x35A]="FloodMessage"
predefined_dictionary_strings[0x35C]="LinkUtility"
predefined_dictionary_strings[0x35E]="Hops"
predefined_dictionary_strings[0x360]="http://schemas.microsoft.com/net/2006/05/peer/HopCount"
predefined_dictionary_strings[0x362]="PeerVia"
predefined_dictionary_strings[0x364]="http://schemas.microsoft.com/net/2006/05/peer"
predefined_dictionary_strings[0x366]="PeerFlooder"
predefined_dictionary_strings[0x368]="PeerTo"
predefined_dictionary_strings[0x36A]="http://schemas.microsoft.com/ws/2005/05/routing"
predefined_dictionary_strings[0x36C]="PacketRoutable"
predefined_dictionary_strings[0x36E]="http://schemas.microsoft.com/ws/2005/05/addressing/none"
predefined_dictionary_strings[0x370]="http://schemas.microsoft.com/ws/2005/05/envelope/none"
predefined_dictionary_strings[0x372]="http://www.w3.org/2001/XMLSchema-instance"
predefined_dictionary_strings[0x374]="http://www.w3.org/2001/XMLSchema"
predefined_dictionary_strings[0x376]="nil"
predefined_dictionary_strings[0x378]="type"
predefined_dictionary_strings[0x37A]="char"
predefined_dictionary_strings[0x37C]="boolean"
predefined_dictionary_strings[0x37E]="byte"
predefined_dictionary_strings[0x380]="unsignedByte"
predefined_dictionary_strings[0x382]="short"
predefined_dictionary_strings[0x384]="unsignedShort"
predefined_dictionary_strings[0x386]="int"
predefined_dictionary_strings[0x388]="unsignedInt"
predefined_dictionary_strings[0x38A]="long"
predefined_dictionary_strings[0x38C]="unsignedLong"
predefined_dictionary_strings[0x38E]="float"
predefined_dictionary_strings[0x390]="double"
predefined_dictionary_strings[0x392]="decimal"
predefined_dictionary_strings[0x394]="dateTime"
predefined_dictionary_strings[0x396]="string"
predefined_dictionary_strings[0x398]="base64Binary"
predefined_dictionary_strings[0x39A]="anyType"
predefined_dictionary_strings[0x39C]="duration"
predefined_dictionary_strings[0x39E]="guid"
predefined_dictionary_strings[0x3A0]="anyURI"
predefined_dictionary_strings[0x3A2]="QName"
predefined_dictionary_strings[0x3A4]="time"
predefined_dictionary_strings[0x3A6]="date"
predefined_dictionary_strings[0x3A8]="hexBinary"
predefined_dictionary_strings[0x3AA]="gYearMonth"
predefined_dictionary_strings[0x3AC]="gYear"
predefined_dictionary_strings[0x3AE]="gMonthDay"
predefined_dictionary_strings[0x3B0]="gDay"
predefined_dictionary_strings[0x3B2]="gMonth"
predefined_dictionary_strings[0x3B4]="integer"
predefined_dictionary_strings[0x3B6]="positiveInteger"
predefined_dictionary_strings[0x3B8]="negativeInteger"
predefined_dictionary_strings[0x3BA]="nonPositiveInteger"
predefined_dictionary_strings[0x3BC]="nonNegativeInteger"
predefined_dictionary_strings[0x3BE]="normalizedString"
predefined_dictionary_strings[0x3C0]="ConnectionLimitReached"
predefined_dictionary_strings[0x3C2]="http://schemas.xmlsoap.org/soap/envelope/"
predefined_dictionary_strings[0x3C4]="actor"
predefined_dictionary_strings[0x3C6]="faultcode"
predefined_dictionary_strings[0x3C8]="faultstring"
predefined_dictionary_strings[0x3CA]="faultactor"
predefined_dictionary_strings[0x3CC]="detail"

prefix_dictionary_elem = Proto ("prefix_dictionary_elem","Binary SOAP prefix dictionary")
prefix_dictionary_elem.fields["desc"] = ProtoField.string("prefix_dictionary_elem.desc", "Description")
function prefix_dictionary_elem.dissector (buf, pkt, root)
  local name_value, off = get_variable_length(buf, 0)
  local str_val = get_value_for_dictionarystring(name_value)
  root:add(prefix_dictionary_elem.fields["desc"], "<"..pkt.private["prefix"]..":"..str_val.." ")
  pkt.private["most_recent_elem"] = pkt.private["prefix"]..":"..str_val.."|"..pkt.private["most_recent_elem"]
  pkt.private["expecting_attributes"] = "true"
  pkt.private["bsoff"] = pkt.private["bsoff"]+off
end
binary_soap_dissector_table:add("PrefixDictionaryElement", prefix_dictionary_elem)

dictionary_elem = Proto ("dictionary_elem","Binary SOAP dictionary elem")
dictionary_elem.fields["desc"] = ProtoField.string("dictionary_elem.desc", "Description")
function dictionary_elem.dissector (buf, pkt, root)
  local prefix_len, off = get_variable_length(buf, 0)
  local prefix = buf(off,prefix_len):string()
  off = off + prefix_len
  local str_id, off = get_variable_length(buf, off)
  local str_val = get_value_for_dictionarystring(str_id)
  root:add(dictionary_elem.fields["desc"], "<"..pkt.private["prefix"]..":"..str_val.." ")
  pkt.private["most_recent_elem"] = pkt.private["prefix"]..":"..str_val.."|"..pkt.private["most_recent_elem"]
  pkt.private["expecting_attributes"] = "true"
  pkt.private["bsoff"] = pkt.private["bsoff"]+off
end
binary_soap_dissector_table:add("DictionaryElement", dictionary_elem)

short_dictionary_elem = Proto ("short_dictionary_elem","Binary SOAP short_dictionary")
short_dictionary_elem.fields["desc"] = ProtoField.string("short_dictionary_elem.desc", "Description")
function short_dictionary_elem.dissector (buf, pkt, root)
  local name_value, off = get_variable_length(buf, 0)
  local str_val = get_value_for_dictionarystring(name_value)
  root:add(short_dictionary_elem.fields["desc"], "<"..str_val.." ")
  pkt.private["most_recent_elem"] = str_val.."|"..pkt.private["most_recent_elem"]
  pkt.private["expecting_attributes"] = "true"
  pkt.private["bsoff"] = pkt.private["bsoff"]+off
end
binary_soap_dissector_table:add("ShortDictionaryElement", short_dictionary_elem)

short_elem = Proto ("short_elem","Binary SOAP short")
short_elem.fields["desc"] = ProtoField.string("short_elem.desc", "Description")
function short_elem.dissector (buf, pkt, root)
  local name_len, off = get_variable_length(buf, 0)
  local str_val = buf(off,name_len):string()
  root:add(short_elem.fields["desc"], "<"..str_val.." ")
  pkt.private["most_recent_elem"] = str_val.."|"..pkt.private["most_recent_elem"]
  pkt.private["expecting_attributes"] = "true"
  pkt.private["bsoff"] = pkt.private["bsoff"]+off+name_len
end
binary_soap_dissector_table:add("ShortElement", short_elem)

string_table_elem = Proto ("string_table_elem","Binary SOAP string table")
local f_bs_string = ProtoField.string("binary_soap.stringtable.string", "String")
string_table_elem.fields = {f_bs_string}
function string_table_elem.dissector (buf, pkt, root)
  local table_size, off = get_variable_length(buf, 0)
  local stream_key = tostring(stream_ex())+tostring(stream_which())
  if string_tables[stream_key] == nil then
    string_tables[stream_key] = {}
  end
  local str_id = table.maxn(string_tables[stream_key])
  if str_id == 0 then
    str_id = 1
  else
    str_id = str_id+2
  end
  --print("Next str_id: "..str_id)
  while off < table_size do
    local str_size = 0
    str_size, off = get_variable_length(buf, off)
    root:add(f_bs_string, "ID:"..str_id.." "..buf(off,str_size):string())
    table.insert(string_tables[stream_key], str_id, buf(off,str_size):string())
    off = off+str_size
    str_id = str_id+2
  end
  pkt.private["bsoff"] = pkt.private["bsoff"]+off
end
binary_soap_dissector_table:add("StringTable", string_table_elem)

function get_value_for_dictionarystring(str_id)
  local str_val = "UNKNOWN"
  local stream_key = tostring(stream_ex())+tostring(stream_which())
  if bit.band(str_id,1) == 0 and predefined_dictionary_strings[str_id] then
    str_val = predefined_dictionary_strings[str_id]
  elseif string_tables[stream_key][str_id] ~= nil then
    str_val = string_tables[stream_key][str_id]
  else
    str_val = "STRID:"..str_id
  end
  --print("String for id: "..str_id.." = "..str_val)
  return str_val
end


dictionary_xmls_elem = Proto ("dictionary_xmls_elem","Binary SOAP XMLNS")
dictionary_xmls_elem.fields = {}
dictionary_xmls_elem.fields["desc"] = ProtoField.string("dictionary_xmls_elem.desc", "Description")
function dictionary_xmls_elem.dissector (buf, pkt, root)
  local prefix_len, off = get_variable_length(buf, 0)
  local prefix = buf(off,prefix_len):string()
  off = off + prefix_len
  local str_id, off = get_variable_length(buf, off)
  local str_val = get_value_for_dictionarystring(str_id)
  root:add(dictionary_xmls_elem.fields["desc"], "xmlns:"..prefix.." = "..str_val)
  pkt.private["bsoff"] = pkt.private["bsoff"]+off
end
binary_soap_dissector_table:add("DictionaryXmlsAttribute", dictionary_xmls_elem)

short_dictionary_xmls_elem = Proto ("short_dictionary_xmls_elem","Binary SOAP short_dictionary_xmls")
short_dictionary_xmls_elem.fields = {}
short_dictionary_xmls_elem.fields["desc"] = ProtoField.string("short_dictionary_xmls_elem.desc", "Description")
function short_dictionary_xmls_elem.dissector (buf, pkt, root)
  local str_id, off = get_variable_length(buf, 0)
  local str_val = get_value_for_dictionarystring(str_id)
  root:add(short_dictionary_xmls_elem.fields["desc"], "xmlns = "..str_val)
  pkt.private["bsoff"] = pkt.private["bsoff"]+off
end
binary_soap_dissector_table:add("ShortDictionaryXmlnsAttribute", short_dictionary_xmls_elem)

prefix_dictionary_xmls_attr = Proto ("prefix_dictionary_xmls_attr","Binary SOAP prefix XMLS attribute")
prefix_dictionary_xmls_attr.fields["desc"] = ProtoField.string("prefix_dictionary_xmls_attr.desc", "Description")
function prefix_dictionary_xmls_attr.dissector (buf, pkt, root)
  local str_id, off = get_variable_length(buf, 0)
  local str_val = get_value_for_dictionarystring(str_id)
  root:add(prefix_dictionary_xmls_attr.fields["desc"], pkt.private["prefix"]..":"..str_val.."=")
  pkt.private["expecting_text"] = "true"
  pkt.private["bsoff"] = pkt.private["bsoff"]+off
end
binary_soap_dissector_table:add("PrefixDictionaryAttribute", prefix_dictionary_xmls_attr)

one_text_record = Proto ("onetext_rec","Binary SOAP onetext")
one_text_record.fields["desc"] = ProtoField.string("onetext_rec.desc", "Description")
function one_text_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  root:add(one_text_record.fields["desc"], "1")
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(dictionary_text_record.fields["desc"], "</"..last_elem..">")
  end
end
binary_soap_dissector_table:add("OneText", one_text_record)


true_text_record = Proto ("true_text_rec","Binary SOAP true_text")
true_text_record.fields["desc"] = ProtoField.string("true_text_rec.desc", "Description")
function true_text_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  root:add(true_text_record.fields["desc"], "true")
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(dictionary_text_record.fields["desc"], "</"..last_elem..">")
  end
end
binary_soap_dissector_table:add("TrueText", true_text_record)

false_text_record = Proto ("false_text_rec","Binary SOAP false_text")
false_text_record.fields["desc"] = ProtoField.string("false_text_rec.desc", "Description")
function false_text_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  root:add(false_text_record.fields["desc"], "false")
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(dictionary_text_record.fields["desc"], "</"..last_elem..">")
  end
end
binary_soap_dissector_table:add("FalseText", false_text_record)

dictionary_text_record = Proto ("dictionary_text_rec","Binary SOAP dictionary_text")
dictionary_text_record.fields["desc"] = ProtoField.string("dictionary_text_rec.desc", "Description")
function dictionary_text_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  local name_value, off = get_variable_length(buf, 0)
  local str_val = get_value_for_dictionarystring(name_value)
  root:add(dictionary_text_record.fields["desc"], str_val)
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(dictionary_text_record.fields["desc"], "</"..last_elem..">")
  end
  pkt.private["bsoff"] = pkt.private["bsoff"]+off
end
binary_soap_dissector_table:add("DictionaryText", dictionary_text_record)

qname_dictionary_record = Proto ("qname_dictionary_rec","Binary SOAP qname_dictionary")
qname_dictionary_record.fields["desc"] = ProtoField.string("qname_dictionary_rec.desc", "Description")
function qname_dictionary_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  local prefix = string.char(buf(0,1):uint()+string.byte("a",1))
  local name_value, off = get_variable_length(buf, 1)
  local str_val = get_value_for_dictionarystring(name_value)
  root:add(qname_dictionary_record.fields["desc"], prefix..":"..str_val)
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(qname_dictionary_record.fields["desc"], "</"..last_elem..">")
  end
  pkt.private["bsoff"] = pkt.private["bsoff"]+off
end
binary_soap_dissector_table:add("QNameDictionaryTextRecord", qname_dictionary_record)



unique_id_text_record = Proto ("unique_id_text_rec","Binary SOAP unique_id_text")
unique_id_text_record.fields["desc"] = ProtoField.string("unique_id_text_rec.desc", "Description")
function unique_id_text_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  root:add(unique_id_text_record.fields["desc"], "urn:uuid:"..tostring(buf(0,4)).."-"..tostring(buf(4,2)).."-"..tostring(buf(6,2)).."-"..tostring(buf(8,8)))
  pkt.private["bsoff"] = pkt.private["bsoff"]+16
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(dictionary_text_record.fields["desc"], "</"..last_elem..">")
  end
end
binary_soap_dissector_table:add("UniqueIdText", unique_id_text_record)


end_elem_record = Proto ("end_elem_rec","Binary SOAP end_elem")
end_elem_record.fields["desc"] = ProtoField.string("end_elem_rec.desc", "Description")
function end_elem_record.dissector (buf, pkt, root)
  local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
  local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
  pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
  root:add(end_elem_record.fields["desc"], "</"..last_elem..">")
end
binary_soap_dissector_table:add("EndElement", end_elem_record)

chars8_text_record = Proto ("chars8_text_rec","Binary SOAP chars8_text")
chars8_text_record.fields["desc"] = ProtoField.string("chars8_text_rec.desc", "Description")
function chars8_text_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  local chars_len = buf(0,1):uint()
  root:add(chars8_text_record.fields["desc"], buf(1,chars_len):string())
  pkt.private["bsoff"] = pkt.private["bsoff"]+1+chars_len
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(dictionary_text_record.fields["desc"], "</"..last_elem..">")
  end
end
binary_soap_dissector_table:add("Chars8Text", chars8_text_record)

datetime_text_record = Proto ("datetime_text_rec","Binary SOAP datetime_text")
datetime_text_record.fields["desc"] = ProtoField.string("datetime_text_rec.desc", "Description")
function datetime_text_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  root:add(datetime_text_record.fields["desc"], tostring(buf(0,8)))
  pkt.private["bsoff"] = pkt.private["bsoff"]+8
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(dictionary_text_record.fields["desc"], "</"..last_elem..">")
  end
end
binary_soap_dissector_table:add("DateTimeText", datetime_text_record)

int8_text_record = Proto ("int8_text_rec","Binary SOAP int8_text")
int8_text_record.fields["desc"] = ProtoField.string("int8_text_rec.desc", "Description")
function int8_text_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  local int_val = buf(0,1):int()
  root:add(int8_text_record.fields["desc"], string.format("%d", int_val))
  pkt.private["bsoff"] = pkt.private["bsoff"]+1
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(dictionary_text_record.fields["desc"], "</"..last_elem..">")
  end
end
binary_soap_dissector_table:add("Int8Text", int8_text_record)

int16_text_record = Proto ("int16_text_rec","Binary SOAP int16_text")
int16_text_record.fields["desc"] = ProtoField.string("int16_text_rec.desc", "Description")
function int16_text_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  local int_val = buf(0,2):int()
  root:add(int16_text_record.fields["desc"], string.format("%d", int_val))
  pkt.private["bsoff"] = pkt.private["bsoff"]+2
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(dictionary_text_record.fields["desc"], "</"..last_elem..">")
  end
end
binary_soap_dissector_table:add("Int16Text", int16_text_record)

bytes8_text_record = Proto ("bytes8_text_rec","Binary SOAP bytes8_text")
bytes8_text_record.fields["data"] = ProtoField.string("bytes8_text_rec.data", "Data")
function bytes8_text_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  local chars_len = buf(0,1):uint()
  root:add(bytes8_text_record.fields["data"], buf(1,chars_len))
  pkt.private["bsoff"] = pkt.private["bsoff"]+1+chars_len
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(dictionary_text_record.fields["desc"], "</"..last_elem..">")
  end
end
binary_soap_dissector_table:add("Bytes8Text", bytes8_text_record)


bytes16_text_record = Proto ("bytes16_text_rec","Binary SOAP bytes16_text")
bytes16_text_record.fields["data"] = ProtoField.string("bytes16_text_rec.data", "Data")
function bytes16_text_record.dissector (buf, pkt, root)
  pkt.private["expecting_text"] = nil
  local chars_len = buf(0,2):le_uint()
  root:add(bytes16_text_record.fields["data"], buf(2,chars_len))
  pkt.private["bsoff"] = pkt.private["bsoff"]+2+chars_len
  if bit.band(pkt.private["rec_type"],1) == 1 then
    local last_elem_idx = string.find(pkt.private["most_recent_elem"],"|")
    local last_elem = pkt.private["most_recent_elem"]:sub(0,last_elem_idx-1)
    pkt.private["most_recent_elem"] = pkt.private["most_recent_elem"]:sub(last_elem_idx+1)
    root:add(dictionary_text_record.fields["desc"], "</"..last_elem..">")
  end
end
binary_soap_dissector_table:add("Bytes16Text", bytes16_text_record)

short_dictionary_attr = Proto ("short_dictionary_attr","Binary SOAP short_dictionary_attr")
short_dictionary_attr.fields = {}
short_dictionary_attr.fields["desc"] = ProtoField.string("short_dictionary_attr.desc", "Description")
function short_dictionary_attr.dissector (buf, pkt, root)
  local str_id, off = get_variable_length(buf, 0)
  local str_val = get_value_for_dictionarystring(str_id)
  root:add(short_dictionary_attr.fields["desc"], str_val.." = ")
  pkt.private["expecting_text"] = "true"
  pkt.private["bsoff"] = pkt.private["bsoff"]+off
end
binary_soap_dissector_table:add("ShortDictionaryAttribute", short_dictionary_attr)

prefix_dictionary_attr = Proto ("prefix_dictionary_attr","Binary SOAP prefix dictionary attribute")
prefix_dictionary_attr.fields["desc"] = ProtoField.string("prefix_dictionary_attr.desc", "Description")
function prefix_dictionary_attr.dissector (buf, pkt, root)
  local str_id, off = get_variable_length(buf, 0)
  local pre_val = get_value_for_dictionarystring(str_id)
  str_id, off = get_variable_length(buf, off)
  local str_val = get_value_for_dictionarystring(str_id)
  root:add(prefix_dictionary_attr.fields["desc"], pre_val..":"..str_val.." = ")
  pkt.private["expecting_text"] = "true"
  pkt.private["bsoff"] = pkt.private["bsoff"]+off
end
binary_soap_dissector_table:add("DictionaryAttribute", prefix_dictionary_attr)


prefix_attr = Proto ("prefix_attr","Binary SOAP prefix attribute")
prefix_attr.fields["desc"] = ProtoField.string("prefix_attr.desc", "Description")
function prefix_attr.dissector (buf, pkt, root)
  local name_len, off = get_variable_length(buf, 0)
  local str_val = buf(off,name_len):string()
  root:add(prefix_attr.fields["desc"], pkt.private["prefix"]..":"..str_val.."=")
  pkt.private["expecting_text"] = "true"
  pkt.private["bsoff"] = pkt.private["bsoff"]+off+name_len
end
binary_soap_dissector_table:add("PrefixAttribute", prefix_attr)
