-- Net8 lua wireshark dissector
-- @drspringfield

-- User to Server request function types
local NET8_USER_FUNC_OLOGON =       1   --  logon to Oracle
local NET8_USER_FUNC_OPENCURSOR =   2   --  Open Cursor
local NET8_USER_FUNC_PARSE =        3   --  Parse
local NET8_USER_FUNC_EXECUTE =      4   --  Execute
local NET8_USER_FUNC_OFETCH =       5   --  fetch a row
local NET8_USER_FUNC_CLOSECURSOR =  8   --  Close Cursor
local NET8_USER_FUNC_OLOGOFF =      9   --  logoff of ORACLE
local NET8_USER_FUNC_ODSCRIBE =    10   --  describe a select list column
local NET8_USER_FUNC_ODEFIN =      11   --  define[] where the column goes
local NET8_USER_FUNC_OCOMON =      12   --  auto[] commit on
local NET8_USER_FUNC_OCOMOFF =     13   --  auto commit off
local NET8_USER_FUNC_OCOMMIT =     14   --  commit
local NET8_USER_FUNC_OROLLBACK =   15   --  rollback
local NET8_USER_FUNC_OSFE =        16   --  set fatal error options
local NET8_USER_FUNC_ORESUME =     17   --  resume current operation
local NET8_USER_FUNC_OVERSN =      18   --  get ORACLE version-date string
local NET8_USER_FUNC_OTEMP =       19   --  until we get rid of OASQL
local NET8_USER_FUNC_CANCEL =      20   --  cancel the current operation
local NET8_USER_FUNC_OGEM =        21   --  get error message
local NET8_USER_FUNC_OEXIT =       22   --  Exit oracle command
local NET8_USER_FUNC_OSPECIAL =    23   --  special function
local NET8_USER_FUNC_OABORT =      24   --  abort
local NET8_USER_FUNC_ODQRID =      25   --  deq by rowid
local NET8_USER_FUNC_OLNGF6 =      26   --  fetch a long column value
local NET8_USER_FUNC_OCAM =        27   --  Create Access Module
local NET8_USER_FUNC_OSAMS =       28   --  Save Access Module Statement
local NET8_USER_FUNC_OSAM =        29   --  Save Access Module
local NET8_USER_FUNC_OPAMS =       30   --  Parse Access Module Statement
local NET8_USER_FUNC_OHOWMANY =    31   --  How Many Items?
local NET8_USER_FUNC_OINIT =       32   --  Initialize Oracle
local NET8_USER_FUNC_OCHANGEU =    33   --  change user id
local NET8_USER_FUNC_OBINDRP =     34   --  Bind by reference positional
local NET8_USER_FUNC_OGETBV =      35   --  Get n'th Bind Variable
local NET8_USER_FUNC_OGETIV =      36   --  Get n'th Into Variable
local NET8_USER_FUNC_OBINDRV =     37   --  Bind by reference
local NET8_USER_FUNC_OBINDRN =     38   --  Bind by reference numeric
local NET8_USER_FUNC_OPARSEX =     39   --  Parse And Execute
local NET8_USER_FUNC_OPARSYN =     40   --  Parse for Syntax only
local NET8_USER_FUNC_OPARSDI =     41   --  Parse for Syntax & SQL Dictionary lookup
local NET8_USER_FUNC_OCONTINUE =   42   --  continue serving after eof
local NET8_USER_FUNC_ODSCRARR =    43   --  array describe
local NET8_USER_FUNC_OLCCINI =     44   --  init sys pars command table
local NET8_USER_FUNC_OLCCFIN =     45   --  finalize sys pars command table
local NET8_USER_FUNC_OLCCPUT =     46   --  put sys par in command table
local NET8_USER_FUNC_OLCCGPI =     47   --  get sys pars info from command table
local NET8_USER_FUNC_OV6STRT =     48   --  start Oracle (V6)
local NET8_USER_FUNC_OV6STOP =     49   --  [poll for] shut down Oracle (V6)
local NET8_USER_FUNC_ORIP =        50   --  run independent process (V6)
local NET8_USER_FUNC_OTRAM =       51   --  test RAM (V6)
local NET8_USER_FUNC_OARCHIVE =    52   --  archive op (V6)
local NET8_USER_FUNC_OMRSTART =    53   --  media recovery - start (V6)
local NET8_USER_FUNC_OMRRECTS =    54   --  media recovery - record tablespace to recover (V6)

local NET8_USER_FUNC_OMRGSLSQ =    55   --  media recovery - get starting log seq # (V6)
local NET8_USER_FUNC_OMRREC =      56   --  media recovery - recover using offline log (V6)
local NET8_USER_FUNC_OMRCAN =      57   --  media recovery - cancel media recovery (V6)
local NET8_USER_FUNC_O2LOGON =     58   --  logon to ORACLE (V6) (supercedes OLOGON)
local NET8_USER_FUNC_OVERSION =    59   --  get ORACLE version-date string in new format
local NET8_USER_FUNC_OINIT2 =      60   --  new init call (supersedes OINIT)
local NET8_USER_FUNC_OCLOALL =     61   --  reserved for MAC; close all cursors
local NET8_USER_FUNC_OALL =        62   --  bundled execution call
local NET8_USER_FUNC_OTEX =        63   --  reserved for os2/msdos; transaction execute call
local NET8_USER_FUNC_OSDAUTH =     64   --  reserved for os2/msdos; set DBA authorization call

local NET8_USER_FUNC_OUDLFUN =     65   --  for direct loader: functions
local NET8_USER_FUNC_OUDLBUF =     66   --  for direct loader: buffer transfer
local NET8_USER_FUNC_OK2RPC =      67   --  distrib. trans. mgr. RPC
local NET8_USER_FUNC_ODSCIDX =     68   --  describe indexes for distributed query
local NET8_USER_FUNC_OSESOPN =     69   --  session operations
local NET8_USER_FUNC_OEXECSCN =    70   --  execute using synchronized system commit numbers
local NET8_USER_FUNC_OALL7 =       71   --  fast upi calls to opial7
local NET8_USER_FUNC_OLONGF =      72   --  Long fetch version 7
local NET8_USER_FUNC_OEXECA =      73   --  call opiexe from opiall; no two-task access
local NET8_USER_FUNC_OSQL7 =       74   --  New ver 7 parse call to deal with various flavour
local NET8_USER_FUNC_OOBS =        75   --  Please DO Not REUSE THIS CODE
local NET8_USER_FUNC_ORPC =        76   --  RPC Call from pl/sql
local NET8_USER_FUNC_OKGL_OLD =    77   --  do a KGL operation
local NET8_USER_FUNC_OEXFEN =      78
local NET8_USER_FUNC_OXAOPN =      79   --  X/Open XA operation
local NET8_USER_FUNC_OKGL =        80   --  New OKGL call
local NET8_USER_FUNC_03LOGON =     81   --  2nd Half of Logon
local NET8_USER_FUNC_03LOGA =      82   --  1st Half of Logon
local NET8_USER_FUNC_OFNSTM =      83   --  Do Streaming Operation
local NET8_USER_FUNC_OPENSESS =    84   --  Open Session
local NET8_USER_FUNC_O71XAOPN =    85   --  X/Open XA operations (71 interface
local NET8_USER_FUNC_ODEBUG =      86   --  debugging operation
local NET8_USER_FUNC_ODEBUGS =     87   --  special debugging operation
local NET8_USER_FUNC_OXAST =       88   --  XA start
local NET8_USER_FUNC_OXACM =       89   --  XA Switch and Commit
local NET8_USER_FUNC_OXAPR =       90   --  XA Switch and Prepare
local NET8_USER_FUNC_OXDP =        91   --  direct copy from db buffers to client addr

--  in Oracle 7 and lower, this used to be OCONNECT
local NET8_USER_FUNC_OKOD =        92   --  New OKOD call

--  Oracle 8 changes follow
local NET8_USER_FUNC_OCBK =        93   --  OCBK call (kernel side only)
local NET8_USER_FUNC_OALL8 =       94   --  new v8 bundled call
local NET8_USER_FUNC_OFNSTM2 =     95   --  OFNSTM without the begintxn
local NET8_USER_FUNC_OLOBOPS =     96   --  LOB and FILE related calls
local NET8_USER_FUNC_OFILECRT =    97   --  FILE create call
local NET8_USER_FUNC_ODNY =        98   --  new describe query call
local NET8_USER_FUNC_OCONNECT =    99   --  code for non blocking attach host
local NET8_USER_FUNC_OOPENRCS =   100   --  Open a recursive cursor
local NET8_USER_FUNC_OKPRALL =    101   --  Bundled KPR execution
local NET8_USER_FUNC_OPLS =       102   --  Bundled PL/SQL execution
local NET8_USER_FUNC_OTXSE =      103   --  transaction start, attach, detach
local NET8_USER_FUNC_OTXEN =      104   --  transaction commit, rollback, recover
local NET8_USER_FUNC_OCCA =       105   --  Cursor Close All
local NET8_USER_FUNC_OFOI =       106   --  Failover info piggyback
local NET8_USER_FUNC_O80SES =     107   --  V8 session switching piggyback
local NET8_USER_FUNC_ODDF =       108   --  Do Dummy Defines
local NET8_USER_FUNC_OLRMINI =    109   --  init sys pars
local NET8_USER_FUNC_OLRMFIN =    110   --  finalize sys pars
local NET8_USER_FUNC_OLRMPUT =    111   --  put sys par in par space
local NET8_USER_FUNC_OLRMTRM =    112   --  terminate sys pars
local NET8_USER_FUNC_OEXFENA =    113   --  execute but don't unmap (used from opiall0)
local NET8_USER_FUNC_OINIUCB =    114   --  OINIT for Untrusted CallBacks
local NET8_USER_FUNC_AUTH =       115   --  Authenticate
local NET8_USER_FUNC_OFGI =       116   --  FailOver Get Instance Info
local NET8_USER_FUNC_OOTCO =      117   --  Oracle Transaction service COmmit remote sites
local NET8_USER_FUNC_GETSESSKEY = 118   --  Get Session Key
local NET8_USER_FUNC_ODSY =       119   --  V8 Describe Any
local NET8_USER_FUNC_OCANA =      120   --  Cancel All
local NET8_USER_FUNC_OAQEQ =      121   --  AQ EnQueue
local NET8_USER_FUNC_OAQDQ =      122   --  AQ Dequeue
local NET8_USER_FUNC_ORFS =       123   --  RFS call
local NET8_USER_FUNC_OKPN =       124   --  Kernel Programmatic Notification
local NET8_USER_FUNC_MAX_OFCN =   124   --  last item allocated

-- extended functions

local NET8_USER_FUNC_OSCID =   0x87   --  OSCID
local NET8_USER_FUNC_OKEYVAL =   0x9a   --  OKEYVAL

-- query results db types in the describe pkt

local NET8_DATATYPE_VARCHAR =           0x01
local NET8_DATATYPE_NUMBER =            0x02
local NET8_DATATYPE_VARNUM =            0x06
local NET8_DATATYPE_LONG =              0x08
local NET8_DATATYPE_DATE =              0x0C
local NET8_DATATYPE_RAW =               0x17
local NET8_DATATYPE_LONG_RAW =          0x18
local NET8_DATATYPE_CHAR =              0x60
local NET8_DATATYPE_RESULT_SET =        0x66
local NET8_DATATYPE_ROWID =             0x68
local NET8_DATATYPE_NAMED_TYPE =        0x6D
local NET8_DATATYPE_REF_TYPE =          0x6F
local NET8_DATATYPE_CLOB =              0x70
local NET8_DATATYPE_BLOB =              0x71
local NET8_DATATYPE_BFILE =             0x72
local NET8_DATATYPE_TIMESTAMP =         0xB4
local NET8_DATATYPE_TIMESTAMPTZ =       0xB5
local NET8_DATATYPE_INTERVALYM =        0xB6
local NET8_DATATYPE_INTERVALDS =        0xB7
local NET8_DATATYPE_TIMESTAMPLTZ =      0xE7
local NET8_DATATYPE_PLSQL_INDEX_TABLE = 0x3E6
local NET8_DATATYPE_FIXED_CHAR =        0x3E7

-- datatype sizes
 
local NET8_DATATYPE_SIZE_TIMESTAMP =          11
local NET8_DATATYPE_SIZE_TIMESTAMPNOFRAC =     7
local NET8_DATATYPE_SIZE_DATE =                7
local NET8_DATATYPE_SIZE_TIMESTAMPZ =         13
local NET8_TIMESTAMPZ_REGIONIDBIT =         0x80 -- -12
local NET8_DATATYPE_SIZE_TIMESTAMPLTZ =       11
local NET8_DATATYPE_SIZE_TIMESTAMPLTZNOFRAC =  7

sqloracle_operation_type = {
    [1] =  "Set protocol" ,
    [2] =  "Set data representations" ,
    [3] =  "TTI call" ,
    [4] =  "Error: No data found" ,
    [5] =  "Access user address space" ,
    [6] =  "Row transfer header" ,
    [7] =  "Row transfer data follows" ,
    [8] =  "Server OK" ,
    [9] =  "Oracle function complete",
    [10] = "N Error return definitions follow",
    [11] = "Sending I/O Vec only for fast UPI",
    [12] = "Send long for fast UPI",
    [13] = "Invoke user callback",
    [14] = "LOB/FILE data follows",
    [15] = "Warning messages - may be a set of them",
    [16] = "Describe information",
    [17] = "TTI call (extended)",
    [18] = "signals special action for untrusted callout support",
    [19] = "Flush Out Bind data in DML/w RETURN when error",
    [32] = "External procedures / service registrations",
    [68] = "External procedures / service registrations 2",
    [0xde] = "Secure Network Services Negotiation",
    [0] =  "Unknown"
 }

sql_func_type = {
    [NET8_USER_FUNC_OLOGON] =     "Logon to Oracle",
    [NET8_USER_FUNC_OPENCURSOR] = "Open" ,
    [NET8_USER_FUNC_PARSE] =      "Query" ,
    [NET8_USER_FUNC_EXECUTE] =    "Execute" ,
    [NET8_USER_FUNC_OFETCH] =     "Fetch" ,
    [NET8_USER_FUNC_CLOSECURSOR] ="Close" ,
    [NET8_USER_FUNC_OLOGOFF] =    "Logoff" ,
    [NET8_USER_FUNC_ODSCRIBE] =   "Describe select list column" ,
    [NET8_USER_FUNC_ODEFIN] =     "Define where column goes" ,
    [NET8_USER_FUNC_OCOMON] =     "Autocommit On" ,
    [NET8_USER_FUNC_OCOMOFF] =    "Autocommit Off" ,
    [NET8_USER_FUNC_OCOMMIT] =    "Commit" ,
    [NET8_USER_FUNC_OROLLBACK] =  "Rollback" ,
    [NET8_USER_FUNC_OSFE] =       "Set fatal error options" ,
    [NET8_USER_FUNC_ORESUME] =    "Resume current operation" ,
    [NET8_USER_FUNC_OVERSN] =     "Get version-date string" ,
    [NET8_USER_FUNC_OTEMP] =      "(Obsolete)" ,
    [NET8_USER_FUNC_CANCEL] =     "Cancel" ,
    [NET8_USER_FUNC_OGEM] =       "Get error message" ,
    [NET8_USER_FUNC_OSPECIAL] =   "Special function" ,
    [NET8_USER_FUNC_OABORT] =     "Abort" ,
    [NET8_USER_FUNC_ODQRID] =     "Dequeue by rowid" ,
    [NET8_USER_FUNC_OLNGF6] =     "Fetch long value" ,
    [NET8_USER_FUNC_OHOWMANY] =   "How Many Items?" ,
    [NET8_USER_FUNC_OINIT] =      "Initialize Database" ,
    [NET8_USER_FUNC_OCHANGEU] =   "Change user_id" ,
    [NET8_USER_FUNC_OBINDRP] =    "Bind by reference positional" ,
    [NET8_USER_FUNC_OGETBV] =     "Get n'th Bind Variable" ,
    [NET8_USER_FUNC_OGETIV] =     "Get n'th Into Variable" ,
    [NET8_USER_FUNC_OBINDRV] =    "Bind by reference" ,
    [NET8_USER_FUNC_OBINDRN] =    "Bind by reference numeric" ,
    [NET8_USER_FUNC_OPARSEX] =    "Parse And Execute" ,
    [NET8_USER_FUNC_OPARSYN] =    "Parse for Syntax only" ,
    [NET8_USER_FUNC_OPARSDI] =    "Parse for Syntax & SQL Dictionary lookup" ,
    [NET8_USER_FUNC_OCONTINUE] =  "Continue serving after eof" ,
    [NET8_USER_FUNC_ODSCRARR] =   "Describe" ,
    [NET8_USER_FUNC_OLCCINI] =    "Init sys pars command table" ,
    [NET8_USER_FUNC_OLCCFIN] =    "Finalize sys pars command table" ,
    [NET8_USER_FUNC_OLCCPUT] =    "Put sys par in command table" ,
    [NET8_USER_FUNC_OV6STRT] =    "Start Oracle (V6)" ,
    [NET8_USER_FUNC_OV6STOP] =    "Poll for shut down Oracle (V6)" ,
    [NET8_USER_FUNC_ORIP] =       "Run independent process (V6)" ,
    [NET8_USER_FUNC_OARCHIVE] =   "Archive op (V6)" ,
    [NET8_USER_FUNC_OMRSTART] =   "Media recovery - start (V6)" ,
    [NET8_USER_FUNC_OMRRECTS] =   "Media recovery - record tablespace to recover (V6)",
    [NET8_USER_FUNC_OMRGSLSQ] =   "Media recovery - get starting log seq # (V6)" ,
    [NET8_USER_FUNC_OMRREC] =     "Media recovery - recover using offline log (V6)" ,
    [NET8_USER_FUNC_OMRCAN] =     "Media recovery - cancel media recovery (V6)" ,
    [NET8_USER_FUNC_O2LOGON] =    "Logon to ORACLE" ,
    [NET8_USER_FUNC_OVERSION] =   "Get Version/Date String" ,
    [NET8_USER_FUNC_OINIT2] =     "New init call (supersedes OINIT)" ,
    [NET8_USER_FUNC_OCLOALL] =    "Reserved for MAC; close all cursors" ,
    [NET8_USER_FUNC_OALL] =       "Bundled execution call" ,
    [NET8_USER_FUNC_OTEX] =       "Transaction execute call (OS/2)" ,
    [NET8_USER_FUNC_OSDAUTH] =    "Set DBA authorization call (OS/2)" ,
    [NET8_USER_FUNC_OUDLFUN] =    "Direct loader: functions" ,
    [NET8_USER_FUNC_OUDLBUF] =    "Direct loader: buffer transfer" ,
    [NET8_USER_FUNC_OK2RPC] =     "Distrib. trans. mgr. RPC" ,
    [NET8_USER_FUNC_ODSCIDX] =    "Describe indexes for distributed query" ,
    [NET8_USER_FUNC_OSESOPN] =    "Session operations" ,
    [NET8_USER_FUNC_OEXECSCN] =   "Execute using synchronized system commit numbers" ,
    [NET8_USER_FUNC_OALL7] =      "New V8 Bundle call" ,
    [NET8_USER_FUNC_OLONGF] =     "Long fetch version 7" ,
    [NET8_USER_FUNC_OEXECA] =     "Call opiexe from opiall" ,
    [NET8_USER_FUNC_OSQL7] =      "Parse call" ,
    [NET8_USER_FUNC_OOBS] =       "(Obsolete)" ,
    [NET8_USER_FUNC_ORPC] =       "RPC Call from pl" ,
    [NET8_USER_FUNC_OEXFEN] =     "OEXFEN" ,
    [NET8_USER_FUNC_OXAOPN] =     "XA operation" ,
    [NET8_USER_FUNC_OKGL] =       "KGL call" ,
    [NET8_USER_FUNC_03LOGON] =    "LogonB",
    [NET8_USER_FUNC_03LOGA] =     "LogonA",
    [NET8_USER_FUNC_OFNSTM] =     "Do Streaming Operation",
    [NET8_USER_FUNC_OPENSESS] =   "Open Session",
    [NET8_USER_FUNC_O71XAOPN] =   "X/Open XA operations",
    [NET8_USER_FUNC_ODEBUG] =     "Debug",
    [NET8_USER_FUNC_ODEBUGS] =    "Special Debug",
    [NET8_USER_FUNC_OXAST] =      "XA Start",
    [NET8_USER_FUNC_OXACM] =      "XA Commit",
    [NET8_USER_FUNC_OXAPR] =      "XA Prepare",
    [NET8_USER_FUNC_OXDP] =       "XA Import",
    [NET8_USER_FUNC_OKOD] =       "Get Object Value From Reference",
    [NET8_USER_FUNC_OCONNECT] =   "Connect",
    [NET8_USER_FUNC_OCBK] =       "call (kernel side only)",
    [NET8_USER_FUNC_OALL8] =      "call (bundled, v8)",
    [NET8_USER_FUNC_OFNSTM2] =    "OFNSTM without the begintxn",
    [NET8_USER_FUNC_OLOBOPS] =    "LOB Operation",
    [NET8_USER_FUNC_OFILECRT] =   "FILE create call",
    [NET8_USER_FUNC_ODNY] =       "New Describe",
    [NET8_USER_FUNC_OCONNECT] =   "code for non blocking attach host",
    [NET8_USER_FUNC_OOPENRCS] =   "Open a recursive cursor",
    [NET8_USER_FUNC_OKPRALL] =    "Bundled KPR execution",
    [NET8_USER_FUNC_OPLS] =       "Bundled PL/SQL execution",
    [NET8_USER_FUNC_OTXSE] =      "transaction start] =attach] =detach",
    [NET8_USER_FUNC_OTXEN] =      "transaction commit] =rollback] =recover",
    [NET8_USER_FUNC_OCCA] =       "Cursor Close All",
    [NET8_USER_FUNC_OFOI] =       "Failover info piggyback",
    [NET8_USER_FUNC_O80SES] =     "V8 session switching piggyback",
    [NET8_USER_FUNC_ODDF] =       "Do Dummy Defines",
    [NET8_USER_FUNC_OLRMINI] =    "init sys pars",
    [NET8_USER_FUNC_OLRMFIN] =    "finalize sys pars",
    [NET8_USER_FUNC_OLRMPUT] =    "put sys par in par space",
    [NET8_USER_FUNC_OLRMTRM] =    "terminate sys pars",
    [NET8_USER_FUNC_OEXFENA] =    "execute but don't unmap (used from opiall0)",
    [NET8_USER_FUNC_OINIUCB] =    "OINIT for Untrusted CallBacks",
    [NET8_USER_FUNC_AUTH] =       "Authenticate",
    [NET8_USER_FUNC_OFGI] =       "FailOver Get Instance Info",
    [NET8_USER_FUNC_OOTCO] =      "Oracle Transaction service COmmit remote sites",
    [NET8_USER_FUNC_GETSESSKEY] = "Get Session Key",
    [NET8_USER_FUNC_ODSY] =       "V8 Describe Any",
    [NET8_USER_FUNC_OCANA] =      "Cancel All",
    [NET8_USER_FUNC_OAQEQ] =      "AQ EnQueue",
    [NET8_USER_FUNC_OAQDQ] =      "AQ Dequeue",
    [NET8_USER_FUNC_ORFS] =       "RFS call",
    [NET8_USER_FUNC_OKPN] =       "Kernel Programmatic Notification",
	[NET8_USER_FUNC_OSCID] = "OSCID",
	[NET8_USER_FUNC_OKEYVAL] = "Set key-values",
    [0] =                         "Unknown type",
}

last_function_seen = 0
TNS_DATA = 6
local net8_header_op = ProtoField.uint8("net8.op", "Header operation", base.DEC, sqloracle_operation_type)
n8_proto = Proto ("net8","Net8")
n8_proto.fields = {net8_header_op, net8_func_type}
-- n8_mgr dissector function
function n8_proto.dissector(buf, pkt, root)
	-- previous TNS dissector
    local tns_length = buf(0,2):uint()

    --debug("Buffer length "..buf:len().." offset "..pkt.desegment_offset)
    if tns_length > buf:len() then
        pkt.desegment_len = tns_length - buf:len()
        pkt.desegment_offset = 0
        return
    else
        tns_dissector:call(buf, pkt, root)

    	local off = 10	
    	local is_data = (buf(4,1):uint() == TNS_DATA)
        
    	pkt.private["is_request"] = (pkt.match_uint == pkt.dst_port)

    	pkt.cols.protocol = n8_proto.name
    	if is_data then
    		pkt.cols.info:set("")
    		n8_buf = buf:range(off):tvb()
    		while n8_buf:len() > 0 do
    			subtree = root:add(n8_proto, n8_buf)

    			subtree:add(net8_header_op, n8_buf(0,1))
    			local op_type_name = sqloracle_operation_type[n8_buf(0,1):uint()]
    			if op_type_name == nil then
    				op_type_name = "Unknown " .. tostring(n8_buf(0,1):uint())
    			end
    			pkt.cols.info:append("Oracle " .. op_type_name)
    			pkt.private["opname"] = op_type_name
    			pkt.private["function_length"] = -1
    			pkt.private["op_length"] = -1
    			n8_op_dissector_table:try(op_type_name, n8_buf:range(1):tvb(), pkt, subtree)
    			if tonumber(pkt.private["function_length"]) >= 0 and tonumber(pkt.private["op_length"]) >= 0 then
    				n8_buf = n8_buf(1+pkt.private["function_length"]+pkt.private["op_length"]):tvb()
    				if n8_buf:len() > 0 then
    					pkt.cols.info:append(", ")
    				end
    			else 
    				break
    			end
    		end
    	end
    end
end

local net8_func_type = ProtoField.uint8("net8.function_type", "Function type", base.DEC, sql_func_type)
n8_function_proto = Proto ("net8.function","Net8 Function")
n8_function_proto.fields = {net8_func_type}
-- n8 func dissector function
function n8_function_proto.dissector(n8_buf, pkt, root)
	local func_type_name = ""
	root:add(net8_func_type, n8_buf(0,1))
	func_type_name = sql_func_type[n8_buf(0,1):uint()]
	last_function_seen = func_type_name
	if func_type_name == nil then
		func_type_name = "Unknown " .. tostring(n8_buf(0,1):uint())
	end
	pkt.cols.info:set("Oracle op " .. pkt.private["opname"] .. ", function " .. func_type_name)
	pkt.private["op_length"] = 1
	n8_func_dissector_table:try(func_type_name, n8_buf:range(1):tvb(), pkt, root)
end

--local generic_bytes = ProtoField.bytes("generic_bytes")

n8_ok_proto = Proto ("net8.ok","Net8 Server OK")
n8_ok_proto.fields.num = ProtoField.uint32("net8.ok.number", "Number key/values", base.DEC)
n8_ok_proto.fields.key = ProtoField.string("net8.ok.key", "Key")
n8_ok_proto.fields.value = ProtoField.string("net8.ok.value", "Value")
n8_ok_proto.fields.kv_flag = ProtoField.uint32("net8.ok.kv_flag", "KV flag")
function n8_ok_proto.dissector (buf, pkt, root)
	if last_function_seen == "Authenticate" or last_function_seen == "Get Session Key" then
		multi_int_data, off = decode_multi_size_int(buf, 0)
		local net8_key_value_key_len = multi_int_data:uint()
		root:add(n8_ok_proto.fields.num, multi_int_data)
		-- key
		for i=0,net8_key_value_key_len-1,1 do
			-- read Key
			multi_int_data, off = decode_multi_size_int(buf, off)
			local key_size = multi_int_data:uint()
			if key_size > 0 then
				clr_string_buf, off = decode_clr_string(buf, off)
				root:add(n8_ok_proto.fields.key, clr_string_buf)
			end

			-- read Value
			multi_int_data, off = decode_multi_size_int(buf, off)
			local value_size = multi_int_data:uint()
			if value_size > 0 then
				clr_string_buf, off = decode_clr_string(buf, off)
				root:add(n8_ok_proto.fields.value, clr_string_buf)
			end

			multi_int_data, off = decode_multi_size_int(buf, off)
			root:add(n8_ok_proto.fields.kv_flag, multi_int_data)
		end
		pkt.private["op_length"] = off
		pkt.private["function_length"] = 0
	end
end

n8_row_transfer_proto = Proto ("net8.rowtransfer","Net8 Row Transfer Header")
n8_row_transfer_proto.fields.flags = ProtoField.uint8("net8.rowtransfer.flag", "Flags", base.HEX)
n8_row_transfer_proto.fields.ncol = ProtoField.uint16("net8.rowtransfer.ncol", "Number Columns", base.DEC)
n8_row_transfer_proto.fields.itern = ProtoField.uint16("net8.rowtransfer.itern", "Iter Number", base.DEC)
n8_row_transfer_proto.fields.niter = ProtoField.uint16("net8.rowtransfer.niter", "Number iters this time", base.DEC)
n8_row_transfer_proto.fields.uaclen = ProtoField.uint16("net8.rowtransfer.uaclen", "UAC Buf length", base.DEC)
n8_row_transfer_proto.fields.dalc = ProtoField.bytes("net8.rowtransfer.dalc", "DALC")
function n8_row_transfer_proto.dissector(buf, pkt, root)
	root:add(n8_row_transfer_proto.fields.flags, buf(0,1))
	local off = 1
	multi_int_data, off = decode_multi_size_int(buf, off)
	root:add(n8_row_transfer_proto.fields.ncol, multi_int_data)
	multi_int_data, off = decode_multi_size_int(buf, off)
	root:add(n8_row_transfer_proto.fields.itern, multi_int_data)
	multi_int_data, off = decode_multi_size_int(buf, off)
	root:add(n8_row_transfer_proto.fields.niter, multi_int_data)
	multi_int_data, off = decode_multi_size_int(buf, off)
	root:add(n8_row_transfer_proto.fields.uaclen, multi_int_data)

	multi_int_data, off = decode_multi_size_int(buf, off)
	local dalc_len = multi_int_data:uint()
	root:add(n8_row_transfer_proto.fields.dalc, dalc_len)
	off = off + dalc_len

	multi_int_data, off = decode_multi_size_int(buf, off)
	dalc_len = multi_int_data:uint()
	root:add(n8_row_transfer_proto.fields.dalc, dalc_len)
	off = off + dalc_len

	pkt.private["op_length"] = off
	pkt.private["function_length"] = 0
end

n8_proto_proto = Proto ("net8.setproto","Net8 Set Protocol")
n8_proto_proto.fields.verstr = ProtoField.string("net8.setproto.verstr", "Version String")
n8_proto_proto.fields.proSvrVer = ProtoField.uint8("net8.setproto.proSvrVer", "Protocol server version")
n8_proto_proto.fields.proSvrStr = ProtoField.stringz("net8.setproto.proSvrStr", "Protocol server string")
n8_proto_proto.fields.svrCharset = ProtoField.uint16("net8.setproto.svrCharset", "Server charset")
n8_proto_proto.fields.svrFlags = ProtoField.uint8("net8.setproto.svrFlags", "Server flags", base.HEX)
function n8_proto_proto.dissector(buf, pkt, root)
	if pkt.private["is_request"] then
		root:add(n8_proto_proto.fields.verstr, buf(7))
		pkt.cols.info:append(" (" .. tostring(buf(7):stringz()) .. ")")
    else
        root:add(n8_proto_proto.fields.proSvrVer, buf(0,1))
        -- skip one
        root:add(n8_proto_proto.fields.proSvrStr, buf(2,50))
        pkt.cols.info:append(" (" .. tostring(buf(2,50):stringz()) .. ")")
        local offset = 2 + buf(2,50):stringz():len()
        root:add(n8_proto_proto.fields.svrCharset, buf(offset,2))
        root:add(n8_proto_proto.fields.svrFlags, buf(offset+2,1))
        local svrCharSetElem = buf(offset+3,1):uint()
        offset = offset + 4 + svrCharSetElem*5
        if buf(0,1):uint() >= 5 then
            -- TODO
        end
	end
end

sns_service_types = {
	[3] = "DataIntegrityService",
	[2] = "EncryptionService",
	[1] = "AuthenticationService",
	[4] = "SupervisorService"
}
sns_field_types = {
    [5] = "version stamp",
    [3] = "short",
    [6] = "status",
    [1] = "raw data",
    [2] = "char"
}
sns_encryption_algos = {
    [0] = "No encryption",
    [1] = "RC4_40",
    [2] = "DES",
    [3] = "DES40",
    [8] = "RC4_56",
    [10] = "RC4_128",
    [12] = "3DES168",
    [15] = "AES128",
    [16] = "AES192",
    [17] = "AES256"
}
sns_checksum_algos = {
    [0] = "No checksum",
    [1] = "MD5",
    [3] = "SHA1"
}
local net8_sns_pkt_size = ProtoField.uint16("net8.sns.pkt_size", "Packet size", base.DEC)
local net8_sns_srv_array_len = ProtoField.uint16("net8.sns.service_array_length", "Service array length", base.DEC)
local net8_sns_srv_type = ProtoField.uint16("net8.sns.service_type", "Service type", base.DEC, sns_service_types)
local net8_sns_srv_cnt = ProtoField.uint16("net8.sns.service_cnt", "Field count", base.DEC)
local net8_sns_srv_bytes = ProtoField.bytes("net8.sns.service_bytes", "Field bytes")
local net8_sns_connection_id = ProtoField.bytes("net8.sns.supervisor.connection_id", "Connection ID")
local net8_sns_srv_version = ProtoField.string("net8.sns.service_version", "Field version")
local net8_sns_srv_ftype = ProtoField.uint16("net8.sns.service_type", "Field type", base.DEC, sns_field_types)
local net8_sns_enc_algo = ProtoField.uint8("net8.sns.encryption.algo", "Encryption algorithm", base.DEC, sns_encryption_algos)
local net8_sns_chk_algo = ProtoField.uint8("net8.sns.checksum.algo", "Checksum algorithm", base.DEC, sns_checksum_algos)
n8_sns_proto = Proto ("net8.sns","Net8 SNS")
n8_sns_proto.fields = {net8_sns_pkt_size, net8_sns_srv_array_len, net8_sns_srv_type, net8_sns_srv_cnt, net8_sns_srv_bytes, net8_sns_srv_ftype, net8_sns_enc_algo, net8_sns_chk_algo, net8_sns_srv_version, net8_sns_connection_id}
-- n8 func dissector function
function n8_sns_proto.dissector(buf, pkt, root)
	-- skip 0xdeadbeef, 3b
	root:add(net8_sns_pkt_size, buf(3,2))
	-- skip indicator, 4b
	root:add(net8_sns_srv_array_len, buf(3+2+4,2))
	-- skip 1b 0
	local off = 3+2+4+2+1
	for i=0,buf(3+2+4,2):uint()-1,1 do
        local service_type = buf(off, 2):uint()
		root:add(net8_sns_srv_type, buf(off, 2))
		off = off + 2
		local service_cnt = buf(off, 2):uint()
		root:add(net8_sns_srv_cnt, buf(off, 2))
		off = off + 2
        -- skip crap (4b 0)
        off = off + 4
        for j=1,service_cnt,1 do
    		-- get byte count
    		local byte_count = buf(off, 2):uint()
    		-- skip byte count
    		off = off + 2
            local field_type = buf(off, 2):uint()
            root:add(net8_sns_srv_ftype, buf(off, 2))
            off = off + 2
            if service_type == 2 and j == 2 then
                local st = root:add("Encryption algorithms", buf(off, byte_count):tvb())
                for k=0,byte_count-1,1 do
                    st:add(net8_sns_enc_algo, buf(off+k, 1))
                end
            elseif service_type == 3 and j == 2 then
                local st = root:add("Checksum algorithms", buf(off, byte_count):tvb())
                for k=0,byte_count-1,1 do
                    st:add(net8_sns_chk_algo, buf(off+k, 1))
                end
            elseif field_type == 5 then
                root:add(net8_sns_srv_version, string.format("%d.%d.%d.%d", buf(off,1):uint(), buf(off+1,1):uint(), buf(off+2,1):uint(), buf(off+3,1):uint()))
            elseif service_type == 4 and j == 2 then
                root:add(net8_sns_connection_id, buf(off, byte_count))
            else
                root:add(net8_sns_srv_bytes, buf(off, byte_count))
            end
    		off = off + byte_count
		end
	end
end

function decode_clr_string(buf, off)
	local clr_size = buf(off, 1):uint()
	off = off + 1
	if clr_size ~= 0xfe then
		return buf(off, clr_size), off+clr_size
	end
	local vsize = buf(off, 1):uint()
	local start_off = off+1
	local out_string = buf(start_off, vsize)
	off = start_off + vsize
	while vsize > 0 do
		vsize = buf(off, 1):uint()
		out_string = out_string .. buf(off+1, vsize)
		off = off + vsize + 1
	end
	return buf(start_off, off-start_off), off
end


function decode_multi_size_int(buf, off)
	local int_size = buf(off, 1):uint()
	if int_size == 0 then
		return buf(off, 1), off+1
	end
	return buf(off+1, int_size), off+1+int_size
end

oracle_oclose = Proto("net8.oclose", "Net8 Cursor Close")
oracle_oclose.fields.cursorIdOffset = ProtoField.uint32("net8.oclose.offset", "Cursor ID offset", base.DEC)
oracle_oclose.fields.cursorId = ProtoField.uint32("net8.oclose.cursor", "Cursor ID", base.DEC)
function oracle_oclose.dissector (buf, pkt, root)
	local off = 2 -- skip ptr
	multi_int_data, off = decode_multi_size_int(buf, off)
	local offset = multi_int_data:uint()
	root:add(oracle_oclose.fields.cursorIdOffset, multi_int_data)

	for i=0,offset-1,1 do
		multi_int_data, off = decode_multi_size_int(buf, off)
		root:add(oracle_oclose.fields.cursorId, multi_int_data)		
	end

	pkt.private["function_length"] = off
end

oracle_set_data_reps = Proto("net8.set_data_reps", "Net8 Set Data Types")
oracle_set_data_reps.fields.clientRIN = ProtoField.uint16("net8.set_data_reps.charset", "Charset")
oracle_set_data_reps.fields.clientFlags = ProtoField.uint8("net8.set_data_reps.flags", "Flags", base.HEX)
oracle_set_data_reps.fields.compileTimeCaps = ProtoField.bytes("net8.set_data_reps.compile_caps", "Compile-time capabilities")
oracle_set_data_reps.fields.runTimeCaps = ProtoField.bytes("net8.set_data_reps.run_caps", "Run-time capabilities")
oracle_set_data_reps.fields.tzbytes = ProtoField.bytes("net8.set_data_reps.timezone", "Timezone")
oracle_set_data_reps.fields.type_and_rep_dty = ProtoField.uint16("net8.set_data_reps.type_and_rep.dty", "Type and Rep dty")
oracle_set_data_reps.fields.type_and_rep_ndty = ProtoField.uint16("net8.set_data_reps.type_and_rep.ndty", "Type and Rep ndty")
oracle_set_data_reps.fields.type_and_rep_rep = ProtoField.uint16("net8.set_data_reps.type_and_rep.rep", "Type and Rep rep")
function oracle_set_data_reps.dissector (buf, pkt, root)
    if pkt.private["is_request"] then
        root:add(oracle_set_data_reps.fields.clientRIN, buf(0,2))
        root:add(oracle_set_data_reps.fields.clientRIN, buf(2,2))
        root:add(oracle_set_data_reps.fields.clientFlags, buf(4,1))
        local capLength = buf(5,1):uint()
        root:add(oracle_set_data_reps.fields.compileTimeCaps, buf(6,capLength))
        local offset = 6+capLength
        local runcapLength = buf(offset,1):uint()
        local are_tz_bytes = false
        root:add(oracle_set_data_reps.fields.runTimeCaps, buf(offset+1,runcapLength))
        if bit.band(buf(offset+2,1):uint(), 1) ~= 0 then
            are_tz_bytes = true
        end
        offset = offset + 1 + runcapLength
        if are_tz_bytes then
            root:add(oracle_set_data_reps.fields.tzbytes, buf(offset,11))
            offset = offset + 11
        end
        while offset < buf:len() - 4 do
            root:add(oracle_set_data_reps.fields.type_and_rep_dty, buf(offset,2))
            offset = offset + 2
            local ndty = buf(offset,2):uint()
            root:add(oracle_set_data_reps.fields.type_and_rep_ndty, buf(offset,2))
            offset = offset + 2
            if ndty ~= 0 then
                root:add(oracle_set_data_reps.fields.type_and_rep_rep, buf(offset,2))
                offset = offset + 4
            end
        end
    end
end


oracle_oauthenticate = Proto ("net8.auth","Net8 Authenticate")
oracle_oauthenticate.fields.logonMode = ProtoField.uint32("net8.auth.logonMode", "Logon Mode", base.HEX)
oracle_oauthenticate.fields.user = ProtoField.string("net8.auth.username", "Username")
oracle_oauthenticate.fields.key = ProtoField.string("net8.auth.key", "Key")
oracle_oauthenticate.fields.value = ProtoField.string("net8.auth.value", "Value")
oracle_oauthenticate.fields.kv_flag = ProtoField.uint32("net8.auth.kv_flag", "KV flag")

function oracle_oauthenticate.dissector (buf, pkt, root)
	local off = 2 -- skip ptr
	multi_int_data, off = decode_multi_size_int(buf, off)
	local user_len = multi_int_data:uint()

	multi_int_data, off = decode_multi_size_int(buf, off)
	root:add(oracle_oauthenticate.fields.logonMode, multi_int_data)

	off = off + 1 -- skip ptr

	multi_int_data, off = decode_multi_size_int(buf, off)
	local kv_list_size = multi_int_data:uint()

	off = off + 2 -- skip 2 ptrs

	root:add(oracle_oauthenticate.fields.user, buf(off, user_len))
	off = off + user_len

	for i=0,kv_list_size-1,1 do
		-- read Key
		multi_int_data, off = decode_multi_size_int(buf, off)
		local key_size = multi_int_data:uint()
		if key_size > 0 then
			clr_string_buf, off = decode_clr_string(buf, off)
			root:add(oracle_oauthenticate.fields.key, clr_string_buf)
		end

		-- read Value
		multi_int_data, off = decode_multi_size_int(buf, off)
		local value_size = multi_int_data:uint()
		if value_size > 0 then
			clr_string_buf, off = decode_clr_string(buf, off)
			root:add(oracle_oauthenticate.fields.value, clr_string_buf)
		end

		multi_int_data, off = decode_multi_size_int(buf, off)
		root:add(oracle_oauthenticate.fields.kv_flag, multi_int_data)
	end
end

local net8_ocall_options = ProtoField.uint32("net8.ocall.options", "Options", base.HEX)
local net8_ocall_cursor = ProtoField.uint32("net8.ocall.cursor", "Cursor", base.DEC)
local net8_ocall_n_rows = ProtoField.uint32("net8.ocall.num_rows", "Number of rows", base.DEC)
local net8_ocall_n_binds = ProtoField.uint32("net8.ocall.num_binds", "Number of bind positions", base.DEC)
local net8_ocall_regid = ProtoField.uint32("net8.ocall.regid", "Registration ID", base.DEC)
local net8_ocall_sql = ProtoField.string("net8.ocall.sql", "SQL statement")
local net8_ocall_al8i4 = ProtoField.uint32("net8.ocall.al8i4", "al8i4", base.DEC)
--local net8_ocall_bytes = ProtoField.bytes("net8.ocall.unknown", "Data")
oracle_ocall_proto = Proto ("net8.ocall","Net8 Call")
oracle_ocall_proto.fields = {net8_ocall_options, net8_ocall_cursor, net8_ocall_n_rows, net8_ocall_n_binds, net8_ocall_sql, net8_ocall_al8i4}
function oracle_ocall_proto.dissector (buf, pkt, root)
	local off = 1
	multi_int_data, off = decode_multi_size_int(buf, off)
	local options = multi_int_data:uint()
	root:add(net8_ocall_options, multi_int_data)

	multi_int_data, off = decode_multi_size_int(buf, off)
	root:add(net8_ocall_cursor, multi_int_data)

	-- is sql statement length zero
	off = off + 1

	multi_int_data, off = decode_multi_size_int(buf, off)
	local sql_stmt_len = multi_int_data:uint()

	-- is al8i4 length zero
	off = off + 1

	multi_int_data, off = decode_multi_size_int(buf, off)
	local al8i4_len = multi_int_data:uint()

	-- two nulls
	off = off + 2

	-- ignore
	multi_int_data, off = decode_multi_size_int(buf, off)

	multi_int_data, off = decode_multi_size_int(buf, off)
	root:add(net8_ocall_n_rows, multi_int_data)

	-- ignore
	multi_int_data, off = decode_multi_size_int(buf, off)


	-- null
	off = off + 1

	multi_int_data, off = decode_multi_size_int(buf, off)
	local n_binds = multi_int_data:uint()
	root:add(net8_ocall_n_binds, multi_int_data)

	-- nulls
	off = off + 5

	-- if(connection.getTTCVersion() >= 2)
	off = off + 1
	multi_int_data, off = decode_multi_size_int(buf, off) -- ignore

	-- if(connection.getTTCVersion() >= 4)
	multi_int_data, off = decode_multi_size_int(buf, off)
	root:add(net8_ocall_regid, multi_int_data)

	-- nulls
	off = off + 2

	-- if(connection.getTTCVersion() >= 5)
	off = off + 1
	multi_int_data, off = decode_multi_size_int(buf, off) -- ignore
	off = off + 1
	multi_int_data, off = decode_multi_size_int(buf, off) -- ignore
	multi_int_data, off = decode_multi_size_int(buf, off) -- ignore


	root:add(net8_ocall_sql, buf(off, sql_stmt_len))
	if sql_stmt_len > 0 then
		pkt.cols.info:append(" SQL (" .. buf(off, sql_stmt_len):string() .. ")")
	end
	off = off + sql_stmt_len

	for i=0,al8i4_len-1,1 do
		multi_int_data, off = decode_multi_size_int(buf, off)
		root:add(net8_ocall_al8i4, multi_int_data)
	end

	if bit.band(options,8) ~= 0 and n_binds > 0 then
		-- bind
		return
	end
	if bit.band(options,16) ~= 0 then
		-- defcols
		return
	end
	--debug("BINDS "..n_binds)
	if bit.band(options,32) ~= 0 and n_binds > 0 then
		-- binds
		return
	end
	pkt.private["function_length"] = off
end

local net8_key_value_flags = ProtoField.uint16("net8.key_value.flags", "Flags", base.DEC)
local net8_key_value_number_kvs = ProtoField.uint32("net8.key_value.number", "Number key/values", base.DEC)
local net8_key_value_ns = ProtoField.string("net8.key_value.namespace", "Namespace")
local net8_key_value_key = ProtoField.string("net8.key_value.key", "Key")
local net8_key_value_value = ProtoField.string("net8.key_value.value", "Value")
local net8_key_value_kv_flag = ProtoField.uint32("net8.key_value.kv_flag", "KV flag")

oracle_key_value_proto = Proto ("net8.key_value","Net8 Key Value")
oracle_key_value_proto.fields = {net8_key_value_ns, net8_key_value_number_kvs, net8_key_value_flags, net8_key_value_key, net8_key_value_value, net8_key_value_kv_flag}
function oracle_key_value_proto.dissector (buf, pkt, root)
	-- byte 0 is padding
	-- byte 1 is 01
	multi_int_data, off = decode_multi_size_int(buf, 2)
	local net8_key_value_ns_len = multi_int_data:uint()
	-- byte 4 is 01 if nbKeyVal > 0
	off = off + 1
	multi_int_data, off = decode_multi_size_int(buf, off)
	local net8_key_value_key_len = multi_int_data:uint()
	root:add(net8_key_value_number_kvs, multi_int_data)
	-- flags UB2
	multi_int_data, off = decode_multi_size_int(buf, off)
	root:add(net8_key_value_flags, multi_int_data)
	-- null ptr
	off = off + 1
	-- namespace
	root:add(net8_key_value_ns, buf(off,net8_key_value_ns_len))
	off = off + net8_key_value_ns_len
	-- key
	for i=0,net8_key_value_key_len-1,1 do
		-- read Key
		multi_int_data, off = decode_multi_size_int(buf, off)
		local key_size = multi_int_data:uint()
		if key_size > 0 then
			clr_string_buf, off = decode_clr_string(buf, off)
			root:add(net8_key_value_key, clr_string_buf)
		end

		-- read Value
		multi_int_data, off = decode_multi_size_int(buf, off)
		local value_size = multi_int_data:uint()
		if value_size > 0 then
			clr_string_buf, off = decode_clr_string(buf, off)
			root:add(net8_key_value_key, clr_string_buf)
		end

		multi_int_data, off = decode_multi_size_int(buf, off)
		root:add(net8_key_value_kv_flag, multi_int_data)
	end
	pkt.private["function_length"] = off
end

local TCP_PORT_TNS = 1521
-- save prior tns_dissector
tns_dissector = DissectorTable.get("tcp.port"):get_dissector(TCP_PORT_TNS)
-- now add n8 dissector to override
DissectorTable.get("tcp.port"):add(TCP_PORT_TNS, n8_proto)

n8_op_dissector_table = DissectorTable.new("net8.op", "Net8 operation", ftypes.STRING)
n8_op_dissector_table:add("TTI call", n8_function_proto)
n8_op_dissector_table:add("TTI call (extended)", n8_function_proto)
n8_op_dissector_table:add("Secure Network Services Negotiation", n8_sns_proto)
n8_op_dissector_table:add("Set protocol", n8_proto_proto)
n8_op_dissector_table:add("Row transfer header", n8_row_transfer_proto)
n8_op_dissector_table:add("Server OK", n8_ok_proto)
n8_op_dissector_table:add("Set data representations", oracle_set_data_reps)

n8_func_dissector_table = DissectorTable.new("net8.function", "Net8 function", ftypes.STRING)
n8_func_dissector_table:add("Set key-values", oracle_key_value_proto)
n8_func_dissector_table:add("call (bundled, v8)", oracle_ocall_proto)
n8_func_dissector_table:add("Authenticate", oracle_oauthenticate)
n8_func_dissector_table:add("Get Session Key", oracle_oauthenticate)
n8_func_dissector_table:add("Cursor Close All", oracle_oclose)

