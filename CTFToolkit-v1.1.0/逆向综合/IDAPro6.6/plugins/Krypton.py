doc = """
#################################################################################
#										#
#  Krypton is an IDA Plugin that assists one in executing a function from IDB	#
#  (IDA database) using IDA's powerful Appcall feature				#
#										#
#  krypton takes xrefs from a given function (say a possible decoder) to  	#
#  find all function calls to it and then parses and finds the parameters used 	#
#  (including prototype, no of arguments, and the arguments themselves) from 	#
#  instructions and uses them to execute the function using appcall, this is 	#
#  most useful in analysing a malware binary with encryption			#
#										#
#  To Install, Copy this file into IDA Plugin folder,				#
#  Std path: "C:\Program Files\IDA\plugins\"					#
#  NOTE: Appcall emulation feature requires IDA >= 5.6				#
#										#
#  Author: Karthik Selvaraj at Symantec Corporation				#
#  Email : neoxfx at gmail dot com						#
#										#
#  Krypton is free software: you can redistribute it and/or modify		#
#  it under the terms of the GNU General Public License as published by		#
#  the Free Software Foundation, either version 3 of the License, or		#
#  (at your option) any later version.						#
#										#
#  This program is distributed in the hope that it will be useful,		#
#  but WITHOUT ANY WARRANTY; without even the implied warranty of		#
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the		#
#  GNU General Public License for more details.					#
#										#
#  You should have received a copy of the GNU General Public License		#
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.	#
#										#
#################################################################################
"""

version     = '1.0'
pluginname  = "Krypton"
pluginVname = pluginname + " " + str(version)
debug       = False
CreateIDC   = True
verbose     = 0

import sys,string,os

def kprint(*s):
    print "[%s]" % pluginname,
    for k in s:
        print k,
    print


try:
    import idautils
    import idc
    from idaapi import *
except:
    kprint ("Error: Use within IDA (>= 5.6)!!")
    print doc
    sys.exit(0)


gsplitChar = "|"
class HelperRoutines:
    """
    This class contains helper routines that the rest of the classes use.
    """
    debug                 = debug
    createIDC             = CreateIDC
    version               = version
    verbose               = verbose
    interConnectInstr     = 'jmp'         # basic block interconnect instruction, in case of spaghetti code
    argPassMech           = "push"
    argPassType           = "__cdecl"
    FILTER                = ''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    logPointer            = None
    logPointerIdc         = None

    def getDataValue(self, addr, size):
        if (size == 1):
            return Byte(addr)
        elif (size == 2):
            return Word(addr)
        elif (size == 4):
            return Dword(addr)
        else:
            self.log(2, "Error! while parsing data: 0x%x --> size: %d" % (addr, size))
            raise

    def log(self, v, cmt):
        if (self.debug) and (v <= self.verbose):
            if self.logPointer == None:
                self.openLogFile("")
            self.logPointer.write(cmt+"\n")

    def logIdc(self, cmt):
        if (self.createIDC):
            #cmt = cmt.translate(self.FILTER)
            if self.logPointerIdc == None:
                self.openIdcLogFile("")
            self.logPointerIdc.write(cmt+"\n")

    def flushlog(self):
        if (self.logPointer != None):
            self.logPointer.flush()
        if (self.logPointerIdc != None):
            self.logPointerIdc.flush()

    def logClose(self):
        if (self.logPointer != None):
            self.logPointer.close()
        if (self.logPointerIdc != None):
            self.logPointerIdc.close()

    def openLogFile(self, fnamePrefix):
        if not self.debug:
            return
        if (self.logPointer != None):
            self.logPointer.close()
        self.logPointer = open(GetIdbPath()+"_%s_%s.log"%(pluginVname, fnamePrefix), "w")
        s = "//%s - LOG file %s" % (pluginVname+fnamePrefix, GetIdbPath())
        self.logPointer.write(s + "\n//" + "=" * len(s) + "\n")

    def openIdcLogFile(self, fnamePrefix):
        if not self.createIDC:
            return
        if (self.logPointerIdc != None):
            self.logPointerIdc.close()
        self.logPointerIdc = open(GetIdbPath()+"_%s_%s.idc"%(pluginVname, fnamePrefix), "w")
        s = "//%s - IDC file %s" % (pluginVname+fnamePrefix, GetIdbPath())
        self.logPointerIdc.write(s + "\n//" + "=" * len(s) + "\n")

    def getXrefs(self, ea):
        a = []
        try:
            a = list(CodeRefsTo(ea, 1))
        except:
            a = []
        return a



class Function(HelperRoutines):

    name               = ""
    ea                 = None
    nargs              = 0
    xrefs              = []
    proto              = ""
    argsSizeArray      = []
    runUntilEA         = {'start':BADADDR, 'end':BADADDR}
    ESCAPE_CODE_BEGIN  = 0xF0
    ArgArrCodes        = {"CONST":0xFE, "BUFFER":0xFF}

    def __init__(self, ea, proto, argSizeArr, argPassMech="push"):

        if ((not isLoaded(ea)) or (proto == None) or (type(proto).__name__ != "str") or (argSizeArr == None)):
            self.log(2, "Error! Bad function parameters! :0x%x" % ea)
            raise
        try:
            self.name   = GetFunctionName(ea)
        except:
            self.name   = "0x%x" % ea

        self.ea     = ea

        if (type(argSizeArr).__name__ == "list"):
            self.nargs  = len(argSizeArr)
            self.argsSizeArray  = argSizeArr
        elif (type(argSizeArr).__name__ == "str"):
            b = eval(argSizeArr)
            self.argsSizeArray = b
            self.nargs = len(self.argsSizeArray)
        else:
            kprint("type:%s" % type(argSizeArr).__name__)
            kprint("arr:%s, %d" % (argSizeArr, len(argSizeArr)))
            kprint("arg array issue!")
            raise

        self.xrefs  = self.getXrefs(ea)

        if len(self.xrefs) == 0:
            self.log(2, "Error! No Xref to function ea :0x%x" % ea)
            raise
        self.proto  = proto
        self.argPassMech    = argPassMech


    def getInstrDataPair(self, i):

        if (i > self.nargs):
            self.log(1, "Error! Index out of Array!! %d" % i)
            raise
        (k,v) = self.argsSizeArray[i]
        if(type(k).__name__ == "str"):
            try:
                k = self.ArgArrCodes[k.upper()]
            except:
                self.log(1, "Error! Unknown code in Argument Array at index: %d" % i)
                kprint("Error! Unknown code \"%s\" in Argument Array \"%s\"" % (k, repr(self.argsSizeArray)))
                raise
        return (k,v)

    def getData(self):
        return self.ea, len(self.xrefs), self.proto, self.argsSizeArray, self.argPassMech

    def getEA(self):
        return self.ea

    def getName(self):
        return self.name

    def updateName(self):
        try:
            oproto = self.proto
            oname  = self.name
            self.name   = GetFunctionName(self.ea)
            if (self.name != oname):
                self.proto = self.proto.replace(oname, self.name)
        except:
            self.name   = oname
            self.proto  = oproto

    def setInitializerExecution(self, initStart, initEnd):
        if ((initStart == BADADDR) or (initEnd == BADADDR)):
            return False
        self.runUntilEA['start'] = initStart
        self.runUntilEA['end'] = initEnd
        kprint("Initializer set for function \"%s\"->EA_RANGE(0x%x, 0x%x)" % (self.name, initStart, initEnd))
        return True

    def __repr__(self):
        global gsplitChar
        return " 0x%x %c %s %c %s %c %s %c (%04d)" % (self.ea, gsplitChar, self.proto, gsplitChar, repr(self.argsSizeArray).split("\""), gsplitChar, self.argPassMech, gsplitChar, len(self.xrefs))



IDBbackedup = False
class DebuggerCtrl(HelperRoutines):
    """
    This class implements debugger control functions, this class makes Appcall calling possible.
    """
    oldDebuggerOptions = None
    modulePath         = ""
    moduleArgs         = ""
    sourceDir          = ""

    def __init__(self):
        self.modulePath = GetInputFilePath()
        self.moduleArgs = ""
        self.sourceDir  = os.path.dirname(GetIdbPath())

    def setSafeGuard(self):
        global IDBbackedup
        self.oldDebuggerOptions = SetDebuggerOptions(DOPT_ENTRY_BPT|DOPT_LIB_MSGS|DOPT_THREAD_BPT|DOPT_START_BPT)
        if not IDBbackedup:
            nam = GetIdbPath()+".bak"
            kprint("Taking IDB Backup to \"%s\"" % nam)
            SaveBase(nam, 0)
            IDBbackedup = True

    def start(self):
        self.setSafeGuard()
        if not os.path.isfile(self.modulePath):
            self.modulePath = idc.AskFile(0,"*.*","Please select the right Path of the module/executable loaded in IDA")
            idc.SetInputFilePath(self.modulePath)
        LoadDebugger("win32", 0) # load win32 as default
        if (StartDebugger(self.modulePath, self.moduleArgs, self.sourceDir) == -1):
            self.log(1, "Error! Failed to launch debugger!")
        GetDebuggerEvent(WFNE_ANY, -1) # handle first event


    def stop(self):
        global pvv
        global decResults
        global decViews

        StopDebugger()

        # workaround for mimic'king persistent view, as StopDebugger will kill all views created
        # hook processExit event and re-create views
        SetDebuggerOptions(self.oldDebuggerOptions)

        evt = 0
        while (GetDebuggerEvent(WFNE_ANY, -1) != PROCESS_EXIT):
            evt += 1

        try:
            pvv = Protoviewer()

            for (k,v) in decViews.iteritems():
                kprint("attempt closing for decView 0x%x" % k)
                v.Close()
                del v

            decViews = {}
            for (ea,x) in decResults.iteritems():
                (fpt, res) = x
                f = protoStr2FunctionInstance(fpt)
                if (f != None):
                    decViews[ea] = decViewer(f)
        except Exception,e:
            kprint("Exception!! @DebuggerCtrl:Stop(), ", e)



class Decryptor(HelperRoutines):
    """
    This Class that executes a given function using Appcall with parameters from all its call references
    """

    tempBuffers           = []
    trackBackLimit        = 10            # instruction trace back limit before the decoder function call
    func                  = None          # instance of class function to hold all attributes
    params                = {}            # parameter hash tree for each reference
    debugCtrl             = None
    decRes                = {}

    def __init__(self, decFunc):
        nprefix = "_%s" % decFunc.getName()
        self.openLogFile(nprefix)
        self.openIdcLogFile(nprefix)
        self.log(1, "\n\nSTART DECRYPTOR\n" + "-"*50)
        self.log(1, "Decryptor function parameters => %s" %  repr(decFunc))
        self.func = decFunc
        self.debugCtrl = DebuggerCtrl()
        decRes = {}

    def _buffer(self, size=256):
        return  Appcall.byref("\x00" * size)

    def cleanup(self):
        self.debugCtrl.stop()
        self.logClose()

    def setResults(self):
        global decResults
        if self.func.getEA() in decResults:
            del decResults[self.func.getEA()]
        if len(self.decRes) > 0:
            decResults[self.func.getEA()] = (repr(self.func), self.decRes,)
            return True
        return False

    def run(self):

        for ref in self.func.xrefs:
            self.log(4, "[-] checking near " + hex(ref))
            self.parseArgs(ref)

        self.debugCtrl.start()
        self.log(1, "[*] debugger launched")

        if (self.func.runUntilEA['end'] != BADADDR) and (self.func.runUntilEA['start'] != BADADDR):
            idc.SetRegValue(self.func.runUntilEA['start'], 'EIP')
            idc.RunTo(self.func.runUntilEA['end'])

        self.decRes = None
        self.decRes = {}

        for ref in self.func.xrefs:
            try:
                arg = self.params[ref]
            except:
                self.log(3, "[-!] Couldn't find arg, skipping call at 0x%x" % ref)
                continue

            try:
                if (self.execute(ref, arg) == -1):
                    break
            except Exception,e:
                kprint("Exception!! @decryptor:run, ", e)
                pass

        self.log(1, "[*] debugger stopped")
        self.log(1, "\n\nEND DECRYPTOR\n" + "-"*50)
        if not self.setResults():
            kprint("No result from function run \"%s\"" % self.func.getName())

        return True

    def execute(self, ref, argv):

        dFunc = Appcall.typedobj(self.func.proto)
        dFunc.ea = self.func.ea
        buffers = []

        try:
            self.log(1, ('[-] Found call @ 0x%x to Decoder - ' % ref) + self.formattedFuncPrint(argv))

            cmd = "dFunc("
            ind = 0
            ibd = 0
            for i in range(self.func.nargs):
                insSize, dataSize = self.func.getInstrDataPair(i)
                if (insSize == self.func.ArgArrCodes["CONST"]):  # const value by ref
                    t = Appcall.byref(dataSize)
                    cmd += "t, "
                elif (insSize == self.func.ArgArrCodes["BUFFER"]):
                    buffers.append(self._buffer(dataSize))
                    cmd += "buffers[%d], " % ibd
                    ibd += 1
                else:
                    cmd += "argv[%d], " % ind
                    ind += 1

            cmd = cmd[:-2] + ")"
            self.log(3, "\tcmd: \"%s\"" % cmd)

            try:
                # This eval is used to convert a python string to a python code statement
                # Appcall is constructed in the string cmd with right parameters before being called
                s = 0
                s = eval(cmd)
            except Exception,e:
                dcode = GetDebuggerEvent(WFNE_ANY, -1)
                if ((dcode == 1) or (dcode == 0x4) or (dcode == 0x200) or (dcode == 0x1000)):
                    pass
                else:
                    dstr = "[!] debugger error code(0x%x), %s" % (dcode, repr(e))
                    self.log(3, dstr)
                    if str(e.__str__()).startswith("Appcall:") or (dcode == -2) or (dcode == -1) or (dcode == 0x40) or (dcode == 0x400):
                        kprint("[!!] Cannot continue! %s" % dstr)
                        kprint("[!!] Stopping script!!")
                        return -1

            self.log(3, "[+] Buffer post decryption @ 0x%x" % ref)

            obbuf = []
            for buff in buffers:
                o = self.parseResult(buff);
                self.log(3, "\tbuffer = \"%s\"" % o)
                if ((type(o).__name__ == 'str') and ((len(o) > 3) or (not repr(o).startswith("\'\\x")))):
                    obbuf.append(o)

            if isLoaded(s):
                try:
                    sdo = GetString(s)
                    if ((sdo != None) and (type(sdo).__name__ == 'str')):
                        self.log(3, "\tRet (eax) buffer = \"%s\"" % sdo)
                        if (not repr(sdo).startswith("\'\\x")):
                            obbuf.append(sdo)
                except:
                    pass

            if isLoaded(Dword(s)):
                try:
                    sdo = GetString(Dword(s))
                    if ((sdo != None) and (type(sdo).__name__ == 'str')):
                        self.log(3, "\tRet Poi(eax) buffer = \"%s\"" % sdo)
                        if (not repr(sdo).startswith("\'\\x")):
                            obbuf.append(sdo)
                except:
                    pass

            rs = max(obbuf, key=len)
            rs = rs.replace("\n", "\\n")
            self.decRes[ref] = rs
            self.logIdc("MakeRptCmt(0x%x, \"%s\");" % (ref, rs.replace("\"", "\\\"")))
            return 0
        except Exception,e:
            kprint("Exception!! @decryptor:execute, ", e)
            pass

    def parseResult(self, buff):
        i = 0
        unicodeStr = ""
        asciiStr = buff.cstr().strip()
        nullFound = False
        # Parse out the unicode string
        while i + 1 < len(buff.value) and not nullFound:
            # Unicode vaules come in as little endian
            aChar = struct.unpack("<H", buff.value[i:i+2])[0]

            if aChar != 0:
                unicodeStr += unichr(aChar)
            else:
                nullFound = True
            i += 2
        # Works on the assumption the buffer will be null-ed out after
        # character data, has worked in practice
        if len(unicodeStr) > len(asciiStr):
            return unicodeStr.encode('ascii', 'ignore')
        else:
            return asciiStr

    def parseArgs(self, ref):

        i = self.trackBackLimit
        argsToParse = self.func.nargs
        argv = []
        ref_p = ref
        while (i and argsToParse):
            insSize, dataSize = self.func.getInstrDataPair(self.func.nargs-argsToParse)
            if (insSize > self.func.ESCAPE_CODE_BEGIN):
                argsToParse -= 1
            else:
                if (dataSize > insSize):
                    self.log(3, "[!!] invalid argument size pair (%d, %d) for arg no: %d" % (insSize, dataSize, self.func.nargs-argsToParse))
                    raise
                ref_p = idc.PrevHead(ref_p, 0)
                if ref_p == BADADDR:
                    break
                disstr = idc.GetDisasm(ref_p)
                if disstr.startswith(self.func.argPassMech) and (idc.ItemSize(ref_p) == insSize):
                    arVal = self.getDataValue(ref_p + insSize - dataSize, dataSize)
                    argv.append(arVal)
                    self.log(4, "Arg found: (0x%x)" % arVal)
                    argsToParse -= 1
                    if not argsToParse:
                        break
                if len(self.getXrefs(ref_p)) == 1:
                    nref = self.getXrefs(ref_p)[0]
                    refins = idc.GetDisasm(nref)
                    if refins.startswith(self.interConnectInstr):
                        ref_p = nref
                i -= 1
        if len(argv) > 0:
            self.log(4, "[-] Adding args for call at 0x%x->%s" % (ref,repr(argv)))
            self.params[ref] = argv

    def formattedFuncPrint(self, argv):

        out = self.func.name + "_" + hex(self.func.ea) + "("
        for arg in argv:
            try:
                out += hex(arg) + ', '
            except:
                out += repr(arg) + ', '
        out = out[:-2]
        out += ")"
        return out


class decViewer(idaapi.simplecustviewer_t):
    decfn  = None

    def __init__(self, fn, reRun = False):
        try:
            if (fn == None):
                raise "No valid decrypt function passed!"
            self.decfn = fn
            if self.Create(reRun):
                self.Show()
            else:
                kprint("unable to create decryptor view!")
                raise
        except Exception,e:
            kprint("Exception!! @decViewer, ", e)

    def Create(self, reRun):
        global pluginVname
        global decResults

        self.menu_write2IDB = None
        self.menu_refresh   = None
        self.menu_write2IDC = None

        if not idaapi.simplecustviewer_t.Create (self, pluginVname + " - " + self.decfn.getName() + " result"):
            kprint("Unable to create view \"%s\"" % pluginVname + " - " + self.decfn.getName() + " result")
            return False

        if reRun or (self.decfn.getEA() not in decResults):
            try:
                if (self.decfn != None):
                    dec = Decryptor(self.decfn)
                    dec.run()
                    dec.cleanup()

            except Exception,e:
                kprint("Exception!! @decViewer:Create in calling decryptor, ", e)

        self.refresh()
        return True

    def refresh(self):
        global decResults
        global gsplitChar
        try:
            self.ClearLines()
            if self.decfn.getEA() in decResults:
                (ea,x) = decResults[self.decfn.getEA()]
                for (k,v) in x.iteritems():
                    cline = idaapi.COLSTR("  0x%08X  %c " % (k, gsplitChar), idaapi.SCOLOR_NUMBER)
                    cline += idaapi.COLSTR("%s" % v, idaapi.SCOLOR_STRING)
                    self.AddLine(cline)
            self.Refresh()
        except Exception,e:
            kprint("Exception!! @decViewer:refresh, ", e)
        return True

    def write2IDB(self):
        global decResults
        try:
            if self.decfn.getEA() in decResults:
                (ea,x) = decResults[self.decfn.getEA()]
                for (k,v) in x.iteritems():
                    MakeRptCmt(k, v)
                kprint("Decrypted strings Written to IDB at respective references!")
        except Exception,e:
            kprint("Exception!! @decViewer:write2IDB, ", e)
        return True


    def OnPopup(self):
        try:
            self.ClearPopupMenu()
            if not self.Count():
                self.AddPopupMenu("-")
                self.menu_refresh   = self.AddPopupMenu("(r) Refresh")
            else:
                self.AddPopupMenu("-")
                self.menu_refresh   = self.AddPopupMenu("(r) Refresh")
                self.menu_write2IDB = self.AddPopupMenu("(w) write these to IDB")

        except Exception,e:
            kprint("Exception!! @decViewer:OnPopup, ", e)
        return True

    def OnPopupMenu(self, menu_id):
        if menu_id == self.menu_refresh:
            self.refresh()

        elif menu_id == self.menu_write2IDB:
            self.write2IDB()

        else:
            return False

        return True

    def GotoLn(self, n):
        global gsplitChar
        if n != 0:
            (ln,b,c) = self.GetLine(n)
            if ln == None:
                return True
            ln = tag_remove(ln)
            l = ln.split(gsplitChar)
            nu = int(l[0],16)
            Jump(nu)
            return True

    def OnDblClick(self, shift):
        n = self.GetLineNo()
        self.GotoLn(n)

    def OnKeydown(self, vkey, shift):
        # escape
        if vkey == 27:
            pass
        # enter
        elif vkey == 13:
            n = self.GetLineNo()
            self.GotoLn(n)

        elif vkey == ord("R"):
            self.refresh()

        elif vkey == ord("W"):
            self.write2IDB()

        else:
            return False

        return True



class ProtoAnalyser(HelperRoutines):
    """
    This class Analyses Function Prototypes and Argument value pairs that can be later used in Appcall
    It analyses Top referenced functions, topNum, default is 10

    """

    allXrefFuncs       = []
    topNum             = 0
    functionlist       = []
    MAX_REFS_TO_CHECK  = 10
    TRACK_BACK_LIMIT   = 10
    MAX_ARGS           = 10
    protoArray         = {}
    argPassMechInsSize = 1
    GCD_THRESOLD       = 70
    no_of_funcs        = 0


    def __init__(self, topN=25):
        self.openLogFile("ProtoAnalyser")
        self.no_of_funcs   = idaapi.get_func_qty()
        if topN > self.no_of_funcs:
            self.topNum = self.no_of_funcs
        else:
            self.topNum = topN
        self.allXrefFuncs  = self.getTopXrefFunctions()

    def cleanup(self):
        self.functionlist  = []
        self.protoArray    = {}
        pass


    def getTopXrefFunctions(self):

        funcs = []
        for fnum in xrange(self.no_of_funcs):
            f_ea = idaapi.getn_func(fnum).startEA
            if f_ea != BADADDR:
                funcs.append((GetFunctionName(f_ea), f_ea, len(self.getXrefs(f_ea)),))
        funcs = sorted(funcs, key=lambda x:x[2], reverse=True)
        return funcs

    def analysePrototype(self, ea, force=False):

        try:
            if not isLoaded(ea):
                self.log(2, "Error! Bad address: 0x%x" % ea)
                raise

            try:
                fname = GetFunctionName(ea)
            except:
                fname = "0x%x" % ea

            xrefs = self.getXrefs(ea)
            if len(xrefs) == 0:
                self.log(3, "Discarding function: %s as there is no xref" % fname)
                return None

            tmpSorterDict  = {}
            mr = self.MAX_REFS_TO_CHECK
            if (len(xrefs) < self.MAX_REFS_TO_CHECK):
                mr = len(xrefs)

            xrefs = xrefs[0:mr]
            self.log(3, "\n%s\nAnalysing prototype for function 0x%x" % ('-'*50,ea))

            if (not force) and (GetFunctionFlags(ea) & (FUNC_HIDDEN|FUNC_LIB)):
                self.log(3, "Discarding function: %s as it is a LIB/HIDDEN function" % fname)
                return None

            idbProto = print_type(ea, False)
            gt = GuessType(ea)
            if (((idbProto != None) and (idbProto.find("__usercall") != -1)) or ((gt != None) and (gt.find("__usercall") != -1))):
                self.argPassMech = "mov"
                self.argPassType = "__usercall"
            else:
                self.argPassType = "__cdecl"
                self.argPassMech = "push"

            for ref in xrefs:
                argvArray      = []
                i = self.TRACK_BACK_LIMIT
                ref_p = ref

                proto = "int %s %s(" % (self.argPassType, fname)

                while (i):
                    g = 0
                    ref_p = idc.PrevHead(ref_p, 0)
                    if ((ref_p == BADADDR) or idc.GetDisasm(ref_p).startswith("call")):
                        g = 2
                        break
                    disstr = idc.GetDisasm(ref_p)
                    if disstr.startswith(self.argPassMech):
                        itmSize = idc.ItemSize(ref_p)
                        if (itmSize == 5):
                            dataVal = self.getDataValue(ref_p + self.argPassMechInsSize, itmSize - self.argPassMechInsSize)
                            if isLoaded(dataVal) and (not isCode(GetFlags(dataVal))):
                                proto += "void*,"
                            else:
                                proto += "int,"
                        elif (itmSize == 2):
                            proto += "int,"
                        else:
                            proto += "int*,"
                            g = 1

                        if g == 0:
                            argvArray.append((itmSize, (itmSize - self.argPassMechInsSize),))
                        else: # push reg
                            argvArray.append(("BUFFER", 0x400,)) # flag to use buffer

                    if len(self.getXrefs(ref_p)) == 1:
                        nref = self.getXrefs(ref_p)[0]
                        refins = idc.GetDisasm(nref)
                        if refins.startswith(self.interConnectInstr):
                            ref_p = nref
                    i -= 1

                if (len(argvArray) == 0):
                    proto += "void,"

                if ((i == 0) or (g == 2)):
                    proto = proto[:-1] + ");"

                self.protoArray[proto] = argvArray
                self.log(4, "Proto, args pattern found at 0x%x is: %s->%s" % (ref, proto, repr(argvArray)))

                try:
                    tmpSorterDict[proto] = tmpSorterDict[proto] + 1
                except:
                    tmpSorterDict[proto] = 1

            itms = sorted(tmpSorterDict.iteritems(), key=lambda (k,v):(v,k), reverse=True)
            (prt, n,) = itms[0]

            if (len(prt.split(",")) > self.MAX_ARGS):
                self.log(2, "too many arguments in proto from protoanalyser, ignoring function")
                return None

            if (idbProto != None):
                self.log(3, "proto from IDB: %s" % idbProto)
                nIdbPrtArgs = len(idbProto.split(","))
                if (nIdbPrtArgs > self.MAX_ARGS):
                    self.log(3, "too many arguments in proto from IDB, ignoring it and using parser found proto")
                    idbProto = prt
                self.log(2, "proto found by parser: %s, occurance: %d" % (prt, n))
                if (len(argvArray) > nIdbPrtArgs):
                    argvArray = argvArray[:nIdbPrtArgs]
                    self.protoArray[prt] = argvArray
                fn = Function(ea, idbProto, self.protoArray[prt], self.argPassMech)
            else:
                fn = Function(ea, prt, self.protoArray[prt], self.argPassMech)

            self.log(2, repr(fn))
            n = (n*100)/mr

            if (not force) and (self.argPassType != "__usercall") and (n < self.GCD_THRESOLD):
                self.log(3, "[GCD of protos from refs is %d%%, discarding above function]" % n)
                return None
            self.log(3, "[GCD of protos from refs is %d%%, considering above function as a candidate, ArgPassMech:%s]" % (n,self.argPassMech))
            return fn

        except Exception,e:
            kprint("Exception!! @analysePrototype, ", e)


    def IsFunctionPresent(self, f):
        for x in self.functionlist:
            if x.getEA() == f.getEA():
                return True
        return False

    def updateProtoFunctionNames(self):
        for x in self.functionlist:
            x.updateName()

    def addfunc(self, f):
        if (f != None):
            if not self.IsFunctionPresent(f):
                self.functionlist.append(f)
                kprint("function \"%s\" added in ProtoAnalyser" % f.getName())
            else:
                kprint("function \"%s\" Already present!" % f.getName())

    def run(self):
        self.cleanup()
        self.log(1, "START prototype analysis...\n" + "-"*50)
        i = self.topNum
        for x in self.allXrefFuncs:
            f = self.analysePrototype(x[1])
            if f != None:
                self.addfunc(f)
                i -= 1
            if (i == 0):
                break
        self.log(1, "END prototype analysis...\n" + "-"*50)
        self.flushlog()


def protoStr2FunctionInstance(s):
    global gsplitChar
    if (s != None) and (type(s).__name__ == "str"):
        np = s.split(gsplitChar)
        ea = int(np[0].strip(),16)
        if isLoaded(ea):
            try:
                return Function(ea, np[1].strip(), np[2].strip(), np[3].strip())
            except:
                kprint("unable to edit item!")
    return None

class Protoviewer (idaapi.simplecustviewer_t):
    global gsplitChar
    splitChar = gsplitChar

    def __init__(self):
        global pa
        if pa == None:
            pa = ProtoAnalyser()
            pa.run()
        self.Create()
        self.Show()

    def Create (self):
        global pa
        global pluginVname

        self.menu_jumpto        = None
        self.menu_deleteitem    = None
        self.menu_edititem      = None
        self.menu_additem       = None
        self.menu_refresh       = None
        self.menu_runAsDecryptor= None
        self.menu_quitPlugin    = None
        self.menu_setInitializerExecution = None

        if not idaapi.simplecustviewer_t.Create (self, pluginVname + " - Top Xref'ed functions"):
            return False
        if pa:
            self.refresh()
        else:
            self.ClearLines()
        return True

    def Cleanup(self):
        global pa
        self.Close()
        if pa != None:
            pa.cleanup()
            pa = None
        return True

    def refresh(self):
        self.ClearLines()
        self.checkItemUpdates()
        header = " Virtual Addr " + self.splitChar + " " * 30 + "  Function Prototype " +  " " * 30 + self.splitChar
        header += " " * 11 + "   Argument Array  " + " " * 11 + self.splitChar + " Type " + self.splitChar + " xrefs"
        self.AddLine(header)
        for line in self.get_colored_lines():
            self.AddLine(line)
        self.Refresh()

    def get_colored_line(self, n):
        ea, nrefs, proto, argSizeArr, argPassMech = self.get_item(n).getData()
        cline = idaapi.COLSTR("  0x%08X  %c " % (ea,self.splitChar), idaapi.SCOLOR_NUMBER)
        proto_v = idaapi.COLSTR("%-80s" % proto, idaapi.SCOLOR_CODNAME)

        argArr_v = idaapi.COLSTR("%c %-40s" % (self.splitChar, repr(argSizeArr)), idaapi.SCOLOR_STRING)
        mech_v = idaapi.COLSTR("%c %-5s" % (self.splitChar,argPassMech), idaapi.SCOLOR_KEYWORD)

        nrefs_v = idaapi.COLSTR("%c (%03d)" % (self.splitChar,nrefs), idaapi.SCOLOR_AUTOCMT)
        cline += proto_v + argArr_v + mech_v + nrefs_v
        return cline

    def get_colored_lines(self):
        lines = []
        for i in xrange (self.get_number_of_items()):
            l = self.get_colored_line(i)
            lines.append(l)
        return lines

    def get_number_of_items(self):
        global pa
        return len(pa.functionlist)

    def checkItemUpdates(self):
        global pa
        pa.updateProtoFunctionNames()

    def get_item(self, n):
        global pa
        return pa.functionlist[n]

    def insert_item(self, n, v):
        global pa
        pa.functionlist.insert(n, v)

    def append_item(self, v):
        global pa
        pa.functionlist.append(v)

    def remove_item(self, n):
        global pa
        pa.functionlist.pop(n)

    def get_item_EA(self, n):
        f = self.get_item(n)
        return f.getEA()

    def get_item_name(self, n):
        f = self.get_item(n)
        return f.getName()

    def update_item(self, n, v):
        global pa
        pa.functionlist[n] = v

    def add_item(self):
        kprint("[TIP] Did you know, you can place your cursor over desired function in dissasembly view and invoke Ctrl+Y to add")
        newProto = AskStr ("0x000000 | int __cdecl func(int, int, int); | [(5,4),(\"const\",0xb0),(\"buffer\",0x100),] | \"push\" | 0", "Enter new prototype")
        if newProto != None:
            try:
                f = protoStr2FunctionInstance(newProto)
                if (f != None):
                    self.append_item(f)
            except:
                kprint("unable to add item!")
        self.refresh()
        return True

    def edit_item(self):
        n = self.GetLineNo()
        if n != 0:
            (ln,b,c) = self.GetLine(n)
            if ln == None:
                return True
            ln = tag_remove(ln)
            l = ln.split(self.splitChar)
            nln = ""
            for x in l:
                nln += x.strip() + " |"
            nln = nln[:-1]
            nps = AskStr (nln, "Please fix prototype")
            if nps != None:
                f = protoStr2FunctionInstance(nps)
                if (f != None):
                    try:
                        self.update_item(n-1, f)
                    except:
                        kprint("unable to edit item!")
            self.refresh()
        return True

    def delete_item(self, ask = True):
        if self.get_number_of_items():
            result = 1
            if ask:
                result = AskYN(1, "Delete item?")
            if result == 1:
                ln = self.GetLineNo()
                if ln != 0:
                    self.remove_item(ln-1)
                    self.refresh()
        return True


    def OnDblClick(self, shift):
        n = self.GetLineNo()
        if n != 0:
            Jump(self.get_item_EA(n-1))
        return True


    def OnHint(self, n):
        global pa
        ret = None
        if n != 0:
            ea = self.get_item_EA(n-1)
            xrefs = pa.getXrefs(ea)
            if len(xrefs) > 0:
                nx = xrefs[0]
                hintStr = ""
                for i in xrange(0, 10):
                    hintStr = idaapi.COLSTR(idc.GetDisasm(nx), idaapi.SCOLOR_MACRO) + "\n" + hintStr
                    nx = idc.PrevHead(nx, 0)
                    if (nx == BADADDR):
                        break
                t = "Code @ First xref 0x%x\n" % xrefs[0]
                hintStr = idaapi.COLSTR(t, idaapi.SCOLOR_NUMBER) + hintStr
                ret = (12, hintStr)
        return ret


    def setInitializerExecution(self):
        n = self.GetLineNo()
        if n!= 0:
            f = self.get_item(n-1)
        else:
            return False

        initCodeSt = idc.BeginEA()
        initCodeSt = idc.AskAddr(initCodeSt, "Enter the start address of the Code Initializer that you want to run before Decryption Routine")
        if initCodeSt == BADADDR:
            kprint ("[!] Cancelled")
            return False

        endCodeSt = initCodeSt + idc.ItemSize(initCodeSt)
        endCodeSt = idc.AskAddr(endCodeSt, "Enter the end address of the Code Initializer that you want to run before Decryption Routine")
        if endCodeSt == BADADDR:
            kprint ("[!] Cancelled")
            return False

        return f.setInitializerExecution(initCodeSt, endCodeSt)


    def runDecryptor(self):
        global decViews
        global decResults
        reRun = False
        n = self.GetLineNo()
        if n!= 0:
            f = self.get_item(n-1)
        else:
            return False
        rf = f.getEA()
        if rf not in decResults:
            ans = AskYN(1, "Run function \"%s\" as decryptor?" % self.get_item_name(n-1))
            if ans != 1:
                return False
        else:
            ans = AskYN(0, "Re-Run function \"%s\" as decryptor?" % self.get_item_name(n-1))
            if ans != 1:
                reRun = False
            else:
                reRun = True
        try:
            v = decViews[rf]
            v.Close()
        except:
            #kprint("view not found for 0x%x creting new one" % rf)
            pass

        decViews[rf] = decViewer(f, reRun)
        return True


    def show_xrefs(self):
        n = self.GetLineNo()
        if n != 0:
            ea = self.get_item_EA(n-1)
            open_xrefs_window(ea)

    def quit_plugin(self):
        global kryptonInst
        kprint("Quiting Plugin, restart with Ctrl+F8");
        self.Cleanup()
        kryptonInst.term()

    def OnKeydown(self, vkey, shift):
        # escape
        if vkey == 27:
            pass
        # enter
        elif vkey == 13:
            n = self.GetLineNo()
            if n != 0:
                Jump (self.get_item_EA(n-1))

        elif vkey == ord('D'):
            self.delete_item()

        elif vkey == ord("E"):
            self.edit_item()

        elif vkey == ord("A"):
            self.add_item()

        elif vkey == ord("R"):
            self.refresh()

        elif vkey == ord("K"):
            self.runDecryptor()

        elif vkey == ord("X"):
            self.show_xrefs()

        elif vkey == ord("I"):
            self.setInitializerExecution()

        elif vkey == ord("Q"):
            self.quit_plugin()

        else:
            return False

        return True


    def OnPopup(self):
        self.ClearPopupMenu()
        if not self.Count():
            self.AddPopupMenu("-")
            self.menu_refresh = self.AddPopupMenu("(r) Refresh")
        else:
            self.AddPopupMenu("-")
            self.menu_refresh = self.AddPopupMenu("(r) Refresh")
            self.menu_refresh = self.AddPopupMenu("(x) Xrefs")
            self.AddPopupMenu("-")
            self.menu_jumpto = self.AddPopupMenu("(Enter) Jump to item address")
            self.menu_edititem = self.AddPopupMenu("(e) Edit Prototype")
            self.AddPopupMenu("-")
            self.menu_additem = self.AddPopupMenu("(a) Add Function Manually")
            self.menu_deleteitem = self.AddPopupMenu("(d) Delete item")
            self.AddPopupMenu("-")
            self.menu_runAsDecryptor  = self.AddPopupMenu("(k) Run As Decryptor")
            self.AddPopupMenu("-")
            self.menu_setInitializerExecution  = self.AddPopupMenu("(i) Set Initializer Execution")
            self.AddPopupMenu("-")
            self.menu_quitPlugin = self.AddPopupMenu("(q) Quit Plugin")

        return True


    def OnPopupMenu(self, menu_id):
        if menu_id == self.menu_refresh:
            self.refresh()

        elif menu_id == self.menu_jumpto:
            n = self.GetLineNo()
            if n!= 0:
                Jump(self.get_item_EA(n-1))

        elif menu_id == self.menu_runAsDecryptor:
            self.runDecryptor()

        elif menu_id == self.menu_deleteitem:
            self.delete_item()

        elif menu_id == self.menu_additem:
            self.add_item()

        elif menu_id == self.menu_edititem:
            self.edit_item()

        elif menu_id == self.menu_setInitializerExecution:
             self.setInitializerExecution()

        elif menu_id == self.menu_quitPlugin:
            self.quit_plugin()

        else:
            return False

        return True

    def OnCursorPosChanged(self):
        self.refresh()
        return True


def addFunctionProtoCB():
    global pa
    global pvv
    try:
        ea = get_func(here()).startEA
        if isLoaded(ea):
            if pvv != None and pa != None:
                f = pa.analysePrototype(ea, True)
                if f != None:
                    pa.addfunc(f)
                    pvv.refresh()
            else:
                kprint("function not added as no instance of protoviewer found!")
        else:
            kprint ("0x%x bad Address!" % here())
    except Exception,e:
        kprint("Exception!! @addFunctionProtoCB, ", e)

def reCreateClosedProtoView():
    global pvv
    if pvv:
        pvv.Close()
    pvv = Protoviewer()


def getProcessorName():
    inf = idaapi.get_inf_structure()
    return inf.procName.strip('\x00')


# Globals
pvv         = None  # protoViewer
decViews    = {}    # decryptViewer instance array for each function decrypted
pa          = None  # protoAnalyser
decResults  = {}    # decryptor results array
kryptonInst = None
PLUGIN_MODE = True

class kplugin_t (idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = pluginVname
    wanted_hotkey = "Ctrl-F8"
    m1 = m3 = None

    def init(self):
        if getProcessorName().startswith('metapc'):
            return PLUGIN_KEEP
        return PLUGIN_SKIP

    def run(self, arg):
        global pvv
        Wait()
        if not pvv:
            pvv = Protoviewer()
            self.m1 = idaapi.add_menu_item("Edit/", pluginVname + " - Add func proto for Decryptor", "Ctrl+Y", 0, addFunctionProtoCB, None)
            if self.m1 == None:
                kprint ("add menu item failed!")
            self.m3 = idaapi.add_menu_item("View/Open subviews/", pluginVname, "", 0, reCreateClosedProtoView, None)
            if self.m3 == None:
                kprint ("add menu item failed!")
        else:
            if not pvv.IsFocused():
                pvv.Close()
                pvv = Protoviewer()

    def term(self):
        global pvv
        if pvv != None:
            pvv.Cleanup()
            pvv = None
        if self.m1 != None:
            idaapi.del_menu_item(self.m1)
        if self.m3 != None:
            idaapi.del_menu_item(self.m3)
        pass

if (PLUGIN_MODE):
    def PLUGIN_ENTRY ():
        global kryptonInst
        kryptonInst = kplugin_t()
        return kryptonInst
else:
    Wait()
    if not pvv:
        pvv = Protoviewer()
    else:
        if not pvv.IsFocused():
            pvv.Close()
            pvv = Protoviewer()
