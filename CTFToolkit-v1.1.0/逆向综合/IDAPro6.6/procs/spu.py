# SPU (Cell Broadband Engine Synergistic Processor Unit)
# Contributed by Felix Domke

import sys
import idaapi
from idaapi import *

# crap crap crap: IDA doesn't store the real python long/int in Opx.value, but only
# a swig'ed version that's going to be unsigned.
# now, if we need to pass that value as a signed value, we need to convert the u32 value
# into a long again... yay.
def fix_sign_32(l):
  l &= 0xFFFFFFFF
  if l & 0x80000000:
    l -= 0x100000000
  return l

# extract bitfield occupying bits high..low from val (inclusive, start from 0)
def BITS(val, high, low):
  return (val>>low)&((1<<(high-low+1))-1)

# extract one bit
def BIT(val, bit):
  return (val>>bit) & 1

# sign extend b low bits in x
# from "Bit Twiddling Hacks"
def SIGNEXT(x, b):
  m = 1 << (b - 1)
  x = x & ((1 << b) - 1)
  return (x ^ m) - m

# check if operand is register reg
def is_reg(op, reg):
    return op.type == o_reg and op.reg == reg

# check if operand is immediate value val
def is_imm(op, val):
    return op.type == o_imm and op.value == val

# is sp delta fixed by the user?
def is_fixed_spd(ea):
    return (get_aflags(ea) & AFL_FIXEDSPD) != 0

def IBITS(val, high, low):
  return BITS(val, 31-high, 31-low)

def decode_RR(opcode):
  # OP, B, A, T
  return IBITS(opcode, 0, 10), IBITS(opcode, 11, 17), IBITS(opcode, 18, 24), IBITS(opcode, 25, 31)

def decode_RRR(opcode):
  # OP, T, B, A, C
  return IBITS(opcode, 0, 3), IBITS(opcode, 4, 10), IBITS(opcode, 11, 17), IBITS(opcode, 18, 24), IBITS(opcode, 25, 31)

def decode_RI7(opcode):
  # OP I RA RT
  return IBITS(opcode, 0, 10), IBITS(opcode, 11, 17), IBITS(opcode, 18, 24), IBITS(opcode, 25, 31)

def decode_RI8(opcode):
  # OP I RA RT
  return IBITS(opcode, 0, 9), IBITS(opcode, 10, 17), IBITS(opcode, 18, 24), IBITS(opcode, 25, 31)

def decode_RI10(opcode):
  # OP I RA RT
  return IBITS(opcode, 0, 7), IBITS(opcode, 8, 17), IBITS(opcode, 18, 24), IBITS(opcode, 25, 31)

def decode_RI16(opcode):
  # OP I RT
  return IBITS(opcode, 0, 8), IBITS(opcode, 9, 24), IBITS(opcode, 25, 31)

def decode_RI18(opcode):
  # OP I RT
  return IBITS(opcode, 0, 6), IBITS(opcode, 7, 24), IBITS(opcode, 25, 31)

def decode_I16RO(opcode):
  # OP ROH I16 ROL
  return IBITS(opcode, 0, 6), IBITS(opcode, 7, 8), IBITS(opcode, 9, 24), IBITS(opcode, 25, 31)

def decode_STOP(opcode):
  # OP TYPE
  return IBITS(opcode, 0, 10), IBITS(opcode, 18, 31)

class spu_processor_t(idaapi.processor_t):
  id = idaapi.PLFM_SPU
  flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE
  cnbits = 8
  dnbits = 8
  psnames = ['spu']
  plnames = ['SPU']
  segreg_size = 0
  instruc_start = 0
  tbyte_size = 0
  assembler = {
    'flag' : ASH_HEXF3 | AS_COLON | ASB_BINF0 | ASO_OCTF1 | AS_NCMAS,
    'uflag' : 0,
    'name': "GNU assembler",
    'origin': ".org",
    'end': "end",
    'cmnt': ";",
    'ascsep': "\"",
    'accsep': "'",
    'esccodes': "\"'",
    'a_ascii': ".ascii",
    'a_byte': ".byte",
    'a_word': ".short",
    'a_dword': ".int",
    'a_qword': ".quad",
    'a_oword': ".int128",
    'a_float': ".float",
    'a_double': ".double",
    #'a_tbyte': "dt",
    #'a_dups': "#d dup(#v)",
    'a_bss': "dfs %s",
    'a_seg': "seg",
    'a_curip': ".",
    'a_public': "public",
    'a_weak': "weak",
    'a_extrn': ".extrn",
    'a_comdef': "",
    'a_align': ".align",
    'lbrace': "(",
    'rbrace': ")",
    'a_mod': "%",
    'a_band': "&",
    'a_bor': "|",
    'a_xor': "^",
    'a_bnot': "~",
    'a_shl': "<<",
    'a_shr': ">>",
    'a_sizeof_fmt': "size %s",
  }

  FL_SIGNED = 0x01  # value/address is signed; output as such
  FL_D      = 0x02  # d suffix (disable interrupts)
  FL_E      = 0x04  # e suffix (enable interrupts)
  FL_C      = 0x08  # c suffix (syncc - sync channels)
  FL_P      = 0x10  # p suffix (inline prefetching)

  # ----------------------------------------------------------------------
  # Processor module callbacks
  #
  # ----------------------------------------------------------------------
  def get_frame_retsize(self, func_ea):
      """
      Get size of function return address in bytes
      SPU doesn't use stack but the link register
      """
      return 0

  # ----------------------------------------------------------------------
  def notify_get_autocmt(self):
      """
      Get instruction comment. 'cmd' describes the instruction in question
      @return: None or the comment string
      """
      if self.cmd.itype in self.comments:
         return self.comments[self.cmd.itype]

  # ----------------------------------------------------------------------
  def is_align_insn(self, ea):
    return 2 if get_word(ea) == 0 else 0

  # ----------------------------------------------------------------------
  def notify_newfile(self, filename):
    pass

  # ----------------------------------------------------------------------
  def notify_oldfile(self, filename):
    pass

  # ----------------------------------------------------------------------
  def add_stkvar(self, v, n, flag):
    pfn = get_func(self.cmd.ea)
    if pfn and ua_stkvar2(self.cmd[n], fix_sign_32(v), flag):
      op_stkvar(self.cmd.ea, n)

  # ----------------------------------------------------------------------
  def handle_operand(self, op, isRead):
    uFlag     = self.get_uFlag()
    is_offs   = isOff(uFlag, op.n)
    dref_flag = dr_R if isRead else dr_W
    def_arg   = isDefArg(uFlag, op.n)
    optype    = op.type

    if optype == o_imm:
      # create xrefs to valid addresses
      makeoff = False
      if self.cmd.itype == self.itype_ila and isLoaded(op.value):
        makeoff = True
      if makeoff and not def_arg:
        set_offset(self.cmd.ea, op.n, self.cmd.cs)
        is_offs = True
      if is_offs:
        ua_add_off_drefs(op, dr_O)
    elif optype == o_displ:
      # create data xrefs and stack vars
      if is_offs:
        ua_add_off_drefs(op, dref_flag)
      elif may_create_stkvars() and not def_arg and op.reg == self.ireg_sp:
        # var_x(SP)
        self.add_stkvar(op.addr, op.n, STKVAR_VALID_SIZE)
    elif optype == o_mem:
      # create data xrefs
      ua_dodata2(op.offb, op.addr, op.dtyp)
      ua_add_dref(op.offb, op.addr, dref_flag)
    elif optype == o_near:
      # create code xrefs
      if self.cmd.get_canon_feature() & CF_CALL:
        fl = fl_CN
      else:
        fl = fl_JN
      ua_add_cref(op.offb, op.addr, fl)

  # ----------------------------------------------------------------------
  def add_stkpnt(self, pfn, v):
      if pfn:
          end = self.cmd.ea + self.cmd.size
          if not is_fixed_spd(end):
              add_auto_stkpnt2(pfn, end, fix_sign_32(v))

  # ----------------------------------------------------------------------
  def trace_sp(self):
    """
    Trace the value of the SP and create an SP change point if the current
    instruction modifies the SP.
    """
    pfn = get_func(self.cmd.ea)
    if not pfn:
        return

    if self.cmd.itype == self.itype_ai and is_reg(cmd.Op1, self.ireg_sp) and is_reg(cmd.Op2, self.ireg_sp) and self.cmd.Op3.type == o_imm:
      # ai sp, sp, #imm
      spofs = self.cmd.Op3.value
      self.add_stkpnt(pfn, spofs)

  # ----------------------------------------------------------------------
  def emu(self):
    Feature = self.cmd.get_canon_feature()

    if Feature & CF_USE1:
        self.handle_operand(self.cmd.Op1, 1)
    if Feature & CF_CHG1:
        self.handle_operand(self.cmd.Op1, 0)
    if Feature & CF_USE2:
        self.handle_operand(self.cmd.Op2, 1)
    if Feature & CF_CHG2:
        self.handle_operand(self.cmd.Op2, 0)
    if Feature & CF_USE3:
        self.handle_operand(self.cmd.Op3, 1)
    if Feature & CF_CHG3:
        self.handle_operand(self.cmd.Op3, 0)
    if Feature & CF_USE4:
        self.handle_operand(self.cmd.Op4, 1)
    if Feature & CF_CHG4:
        self.handle_operand(self.cmd.Op4, 0)
    if Feature & CF_JUMP:
        QueueSet(Q_jumps, self.cmd.ea)

    flow = (Feature & CF_STOP == 0)
    if flow:
      ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

    # create stack vars for ai rd, sp, offs
    # only if rd != sp
    if may_create_stkvars() and self.cmd.itype == self.itype_ai \
          and is_reg(self.cmd.Op2, self.ireg_sp) and not is_reg(self.cmd.Op1, self.ireg_sp) \
          and self.cmd.Op3.type == o_imm and not isDefArg(self.get_uFlag(), 2):
      self.add_stkvar(self.cmd.Op3.value, 2, 0)

    # trace the stack pointer if:
    #   - it is the second analysis pass
    #   - the stack pointer tracing is allowed
    if may_trace_sp():
        if flow:
            self.trace_sp()         # trace modification of SP register
        else:
            recalc_spd(self.cmd.ea) # recalculate SP register for the next insn

    return 1

  # ----------------------------------------------------------------------
  def outop(self, op):
    optype = op.type
    fl     = op.specval
    signed = OOF_SIGNED if fl & self.FL_SIGNED != 0 else 0
    if optype == o_reg:
      out_register(self.regNames[op.reg])
    elif optype == o_imm:
      OutValue(op, OOFW_IMM | signed | (OOFW_32 if self.PTRSZ == 4 else OOFW_64))
    elif optype in [o_near, o_mem]:
      r = out_name_expr(op, op.addr, BADADDR)
      if not r:
        out_tagon(COLOR_ERROR)
        OutLong(op.addr, 16)
        out_tagoff(COLOR_ERROR)
        QueueSet(Q_noName, self.cmd.ea)
    elif optype == o_displ:
        OutValue(op, OOF_ADDR | (OOFW_32 if self.PTRSZ == 4 else OOFW_64) | signed )
        out_symbol('(')
        out_register(self.regNames[op.reg])
        out_symbol(')')
    return True

  # ----------------------------------------------------------------------
  def out(self):
    buf = idaapi.init_output_buffer(1024)

    postfix = ""

    if self.cmd.auxpref & self.FL_D:
      postfix += "d"

    if self.cmd.auxpref & self.FL_E:
      postfix += "e"

    if self.cmd.auxpref & self.FL_P:
      postfix += "p"

    if self.cmd.auxpref & self.FL_C:
      postfix += "c"

    OutMnem(15, postfix)

    out_one_operand(0)

    for i in range(1, 4):
        op = self.cmd[i]

        if op.type == o_void:
            break

        out_symbol(',')
        OutChar(' ')
        out_one_operand(i)

    term_output_buffer()

    cvar.gl_comm = 1
    MakeLine(buf)

  # ----------------------------------------------------------------------
  # replace some instructions by simplified mnemonics
  def simplify(self):
    # ori rt, ra, 0 -> lr ri, ra
    if self.cmd.itype in [self.itype_ori, self.itype_shlqbyi] and self.cmd.Op3.value == 0:
      self.cmd.itype = self.itype_lr
      self.cmd.Op3.type = o_void

  # ----------------------------------------------------------------------
  def ana(self):
    opcode = ua_next_long()

    ins = self.itable[IBITS(opcode, 0, 10)]

    if ins is None:
      return 0

    self.cmd.itype = getattr(self, 'itype_' + ins.name)
    for c in self.cmd:
      c.type = o_void
    ins.decode(self, opcode)
    self.simplify()
    return self.cmd.size

  # ----------------------------------------------------------------------
  def init_instructions(self):

    class idef:
      pass

    class idef_RR(idef):
      def __init__(self, name):
        self.name = name
        self.cf = CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3

      def decode(self, p, opcode):
        _, p.cmd.Op3.reg, p.cmd.Op2.reg, p.cmd.Op1.reg = decode_RR(opcode)
        p.cmd.Op1.type = p.cmd.Op2.type = p.cmd.Op3.type = o_reg

    class idef_ROHROL(idef_RR):
      def __init__(self, name):
        self.name = name
        self.cf = 0

      def decode(self, p, opcode):
        _, roh, p.cmd.Op2.reg, rol = decode_RR(opcode)

        prefetch = roh & 0x40 != 0

        roh &= 3

        val = roh << 7 | rol

        if val & 0x100:
          val -= 0x200

        val <<= 2

        p.cmd.Op1.type = o_mem
        p.cmd.Op1.addr = val + p.cmd.ea
        p.cmd.Op2.type = o_reg
        if prefetch:
          p.cmd.auxpref |= spu_processor_t.FL_P
          if p.cmd.Op2.reg == 0:
            p.cmd.Op2.type = o_void
            if val == 0:
              p.cmd.Op1.type = o_void

    class idef_R(idef_RR):
      def __init__(self, name, noRA = False):
        self.name = name
        self.noRA = noRA
        if noRA:
          self.cf = CF_CHG1
        else:
          self.cf = CF_CHG1 | CF_USE2

      def decode(self, p, opcode):
        idef_RR.decode(self, p, opcode)
        p.cmd.Op3.type = o_void
        if self.noRA and p.cmd.Op2.reg == 0:
          p.cmd.Op2.type = o_void

    class idef_SPR(idef):
      def __init__(self, name, swap = False, offset = 128):
        self.name = name
        self.swap = swap
        self.offset = offset
        self.cf = CF_USE1 | CF_CHG1 | CF_USE2

      def decode(self, p, opcode):
        _, _, p.cmd.Op2.reg, p.cmd.Op1.reg = decode_RR(opcode)
        p.cmd.Op1.type = o_reg
        p.cmd.Op2.type = o_reg
        p.cmd.Op2.reg += self.offset
        if self.swap:
          (p.cmd.Op1.type, p.cmd.Op1.reg, p.cmd.Op2.type, p.cmd.Op2.reg) = \
          (p.cmd.Op2.type, p.cmd.Op2.reg, p.cmd.Op1.type, p.cmd.Op1.reg)


    class idef_CH(idef_SPR):
      def __init__(self, name, swap = False):
        idef_SPR.__init__(self, name, swap, 256)

    class idef_noops(idef):
      def __init__(self, name, cbit = False):
        self.name = name
        self.cbit = cbit
        self.cf = 0

      def decode(self, p, opcode):
        _, p.cmd.Op3.reg, p.cmd.Op2.reg, p.cmd.Op1.reg = decode_RR(opcode)
        p.cmd.Op1.type = p.cmd.Op2.type = p.cmd.Op3.type = o_reg
        if self.cbit and p.cmd.Op3.reg & 0x40 != 0:
          p.cmd.auxpref |= spu_processor_t.FL_C
          p.cmd.Op3.reg &= ~0x40

        if p.cmd.Op3.reg == 0:
          p.cmd.Op3.type = o_void
          if p.cmd.Op2.reg == 0:
            p.cmd.Op2.type = o_void
            if p.cmd.Op1.reg == 0:
              p.cmd.Op1.type = o_void

    class idef_RRR(idef):
      def __init__(self, name):
        self.name = name
        self.cf = CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4

      def decode(self, p, opcode):
        _, p.cmd.Op1.reg, p.cmd.Op3.reg, p.cmd.Op2.reg, p.cmd.Op4.reg = decode_RRR(opcode)
        p.cmd.Op1.type = p.cmd.Op2.type = p.cmd.Op3.type = p.cmd.Op4.type = o_reg

    class idef_Branch(idef_RR):
      def __init__(self, name, no2 = False, uncond = False):
        self.name = name
        self.cf = CF_USE1 | CF_JUMP
        if uncond:
          self.cf |= CF_STOP
        self.no2 = no2

      def decode(self, p, opcode):
        _, flags, p.cmd.Op2.reg, p.cmd.Op1.reg = decode_RR(opcode)
        p.cmd.Op1.type = p.cmd.Op2.type = o_reg

        if self.no2:
          p.cmd.Op2.type = o_void
          p.cmd.Op1.reg = p.cmd.Op2.reg
        if flags & 0x10:
          p.cmd.auxpref |= spu_processor_t.FL_E
        if flags & 0x20:
          p.cmd.auxpref |= spu_processor_t.FL_D

    class idef_RI7(idef):
      def __init__(self, name, signed = True):
        self.name = name
        self.signed = signed
        self.cf = CF_USE1 | CF_CHG1 | CF_USE2

      def decode(self, p, opcode):
        _, p.cmd.Op3.value, p.cmd.Op2.reg, p.cmd.Op1.reg = decode_RI7(opcode)
        p.cmd.Op1.type = p.cmd.Op2.type = o_reg
        p.cmd.Op3.type = o_imm
        if self.signed and p.cmd.Op3.value & 0x40:
          p.cmd.Op3.value -= 0x80
          p.cmd.Op3.specval |= spu_processor_t.FL_SIGNED

    class idef_RI8(idef):
      def __init__(self, name, bias):
        self.name = name
        self.bias = bias
        self.cf = CF_CHG1 | CF_USE2 | CF_USE3

      def decode(self, p, opcode):
        _, p.cmd.Op3.value, p.cmd.Op2.reg, p.cmd.Op1.reg = decode_RI8(opcode)
        p.cmd.Op1.type = p.cmd.Op2.type = o_reg
        p.cmd.Op3.value = self.bias - p.cmd.Op3.value
        p.cmd.Op3.type = o_imm

    class idef_RI7_ls(idef_RI7):
      def decode(self, p, opcode):
        _, p.cmd.Op2.addr, p.cmd.Op2.reg, p.cmd.Op1.reg = decode_RI7(opcode)
        p.cmd.Op1.type = o_reg
        p.cmd.Op2.type = o_displ
        p.cmd.Op2.dtyp = dt_byte16
        if p.cmd.Op2.addr & 0x40:
          p.cmd.Op2.addr -= 0x80
          p.cmd.Op2.specval |= spu_processor_t.FL_SIGNED

    class idef_RI10(idef):
      def __init__(self, name, signed = True):
        self.name = name
        self.signed = signed
        self.cf = CF_USE1 | CF_CHG1 | CF_USE2

      def decode(self, p, opcode):
        _, p.cmd.Op3.value, p.cmd.Op2.reg, p.cmd.Op1.reg = decode_RI10(opcode)
        p.cmd.Op1.type = p.cmd.Op2.type = o_reg
        p.cmd.Op3.type = o_imm
        if self.signed:
          if p.cmd.Op3.value & 0x200:
            p.cmd.Op3.value -= 0x400
            p.cmd.Op3.specval |= spu_processor_t.FL_SIGNED

    class idef_RI10_ls(idef_RI10):
      def decode(self, p, opcode):
        _, p.cmd.Op2.addr, p.cmd.Op2.reg, p.cmd.Op1.reg = decode_RI10(opcode)
        p.cmd.Op1.type = o_reg
        p.cmd.Op2.type = o_displ
        p.cmd.Op2.addr <<= 4
        p.cmd.Op2.dtyp = dt_byte16
        if p.cmd.Op2.addr & 0x2000:
          p.cmd.Op2.addr -= 0x4000
          p.cmd.Op2.specval |= spu_processor_t.FL_SIGNED

    class idef_RI16(idef):
      def __init__(self, name, flags = 0, noRA = False, isBranch = True, signext = False):
        self.name = name
        self.noRA = noRA
        self.isBranch = isBranch
        self.signext = signext

        self.cf = CF_USE1 | CF_CHG1 | CF_USE2 | flags
        if noRA:
          self.cf &= ~(CF_USE2|CF_CHG2)

      def decode(self, p, opcode):
        _, p.cmd.Op2.value, p.cmd.Op1.reg = decode_RI16(opcode)
        p.cmd.Op1.type = o_reg
        p.cmd.Op2.type = o_imm
        if self.signext and p.cmd.Op2.value & 0x8000:
          p.cmd.Op2.value -= 0x10000
          p.cmd.Op2.specval |= spu_processor_t.FL_SIGNED
        self.fixRA(p)

      def fixRA(self, p):
        if self.noRA:
          p.cmd.Op1.addr, p.cmd.Op1.type, p.cmd.Op2.type = p.cmd.Op2.addr, p.cmd.Op2.type, o_void

    class idef_RI16_abs(idef_RI16):
      def decode(self, p, opcode):
        idef_RI16.decode(self, p, opcode)
        p.cmd.Op2.addr = p.cmd.Op2.value << 2
        self.fixOp2(p)
        self.fixRA(p)

      def fixOp2(self, p):
        if self.isBranch:
           p.cmd.Op2.type = o_near
        else:
           # lqr/lqa/stqr/stqa
           p.cmd.Op2.type = o_mem
           p.cmd.Op2.dtyp = dt_byte16

    class idef_RI16_rel(idef_RI16_abs):
      def decode(self, p, opcode):
        idef_RI16.decode(self, p, opcode)
        p.cmd.Op2.addr = (p.cmd.Op2.value << 2) + p.cmd.ea
        if p.cmd.Op2.addr & 0x40000:
          p.cmd.Op2.addr &=~0x40000
        self.fixOp2(p)
        self.fixRA(p)

    class idef_RI18(idef):
      def __init__(self, name):
        self.name = name
        self.cf = CF_USE1 | CF_CHG1 | CF_USE2

      def decode(self, p, opcode):
        _, p.cmd.Op2.value, p.cmd.Op1.reg = decode_RI18(opcode)
        p.cmd.Op1.type = o_reg
        p.cmd.Op2.type = o_imm
        p.cmd.Op2.dtyp = dt_dword

    class idef_I16RO(idef):
      def __init__(self, name, rel = False):
        self.name = name
        self.cf = 0
        self.rel = rel

      def decode(self, p, opcode):
        _, roh, i16, rol = decode_I16RO(opcode)
        val = (roh << 7) | rol

        if val & 0x200:
          val -= 0x400

        val <<= 2

        if self.rel:
          # i16 is signed relative offset
          if i16 & 0x8000:
            i16 -= 0x10000
          i16 = p.cmd.ea + (i16 << 2)
        else:
          i16 <<= 2

        p.cmd.Op1.type = o_mem
        p.cmd.Op1.addr = val + p.cmd.ea
        p.cmd.Op2.type = o_near
        p.cmd.Op2.addr = i16

    class idef_stop(idef):
      def __init__(self, name):
        self.name = name
        self.cf = CF_STOP | CF_USE1

      def decode(self, p, opcode):
        _, t = decode_STOP(opcode)
        p.cmd.Op1.type = o_imm
        p.cmd.Op1.value = t

    self.itable_RI10 = {
       0x04: idef_RI10("ori"),
       0x05: idef_RI10("orhi"),
       0x06: idef_RI10("orbi"),
       0x0c: idef_RI10("sfi"),
       0x0d: idef_RI10("sfhi"),
       0x14: idef_RI10("andi"),
       0x15: idef_RI10("andhi"),
       0x16: idef_RI10("andbi"),
       0x1c: idef_RI10("ai"),
       0x1d: idef_RI10("ahi"),
       0x24: idef_RI10_ls("stqd"),
       0x34: idef_RI10_ls("lqd"),
       0x44: idef_RI10("xori"),
       0x45: idef_RI10("xorhi"),
       0x46: idef_RI10("xorbi", signed = False),
       0x4c: idef_RI10("cgti"),
       0x4d: idef_RI10("cgthi"),
       0x4e: idef_RI10("cgtbi"),
       0x4f: idef_RI10("hgti"),  # false target
       0x5c: idef_RI10("clgti"),
       0x5d: idef_RI10("clgthi"),
       0x5e: idef_RI10("clgtbi"),
       0x5f: idef_RI10("hlgti"), # false target
       0x74: idef_RI10("mpyi"),
       0x75: idef_RI10("mpyui"),
       0x7c: idef_RI10("ceqi"),
       0x7d: idef_RI10("ceqhi"),
       0x7e: idef_RI10("ceqbi"),
       0x7f: idef_RI10("heqi"),
    }

    # 11-bit opcodes (bits 0:10)
    self.itable_RR = {
      0x000: idef_stop("stop"),
      0x001: idef_noops("lnop"), # no regs
      0x002: idef_noops("sync", cbit = True), # C/#C
      0x003: idef_noops("dsync"), # no regs
      0x00c: idef_SPR("mfspr"), # SA = number
      0x00d: idef_CH("rdch"), # //, CA, RT
      0x00f: idef_CH("rchcnt"), # //, CA, RT
      0x040: idef_RR("sf"),
      0x041: idef_RR("or"),
      0x042: idef_RR("bg"),
      0x048: idef_RR("sfh"),
      0x049: idef_RR("nor"),
      0x053: idef_RR("absdb"),
      0x058: idef_RR("rot"),
      0x059: idef_RR("rotm"),
      0x05a: idef_RR("rotma"),
      0x05b: idef_RR("shl"),
      0x05c: idef_RR("roth"),
      0x05d: idef_RR("rothm"),
      0x05e: idef_RR("rotmah"),
      0x05f: idef_RR("shlh"),
      0x07f: idef_RR("shlhi"),
      0x0c0: idef_RR("a"),
      0x0c1: idef_RR("and"),
      0x0c2: idef_RR("cg"),
      0x0c8: idef_RR("ah"),
      0x0c9: idef_RR("nand"),
      0x0d3: idef_RR("avgb"),
      0x10c: idef_SPR("mtspr", swap=1), # SA = number
      0x10d: idef_CH("wrch", swap=1), # // CA RT
      0x128: idef_Branch("biz"),  # branch
      0x129: idef_Branch("binz"), # branch
      0x12a: idef_Branch("bihz"), # branch
      0x12b: idef_Branch("bihnz"), # branch
      0x140: idef_RR("stopd"),
      0x144: idef_RR("stqx"),
      0x1a8: idef_Branch("bi", no2 = True, uncond = True),   # branch
      0x1a9: idef_Branch("bisl"), # branch
      0x1aa: idef_Branch("iret", no2 = True, uncond = True), # branch
      0x1ab: idef_Branch("bisled"), # branch
      0x1ac: idef_ROHROL("hbr"),   # ROH/ROL form
      0x1b0: idef_R("gb"),    # no first reg
      0x1b1: idef_R("gbh"),   # no first reg
      0x1b2: idef_R("gbb"),   # no first reg
      0x1b4: idef_R("fsm"),   #  no first reg
      0x1b5: idef_R("fsmh"),  # no first reg
      0x1b6: idef_R("fsmb"),  # no first reg
      0x1b8: idef_R("frest"), # no first reg
      0x1b9: idef_R("frsqest"), # no first reg
      0x1c4: idef_RR("lqx"),
      0x1cc: idef_RR("rotqbybi"),
      0x1cd: idef_RR("rotqmbybi"),
      0x1cf: idef_RR("shlqbybi"),
      0x1d4: idef_RR("cbx"),
      0x1d5: idef_RR("chx"),
      0x1d6: idef_RR("cwx"),
      0x1d7: idef_RR("cdx"),
      0x1d8: idef_RR("rotqbi"),
      0x1d9: idef_RR("rotqmbi"),
      0x1db: idef_RR("shlqbi"),
      0x1dc: idef_RR("rotqby"),
      0x1dd: idef_RR("rotqmby"),
      0x1df: idef_RR("shlqby"),
      0x1f0: idef_R("orx"), # no first reg
      0x201: idef_noops("nop"), # no regs
      0x240: idef_RR("cgt"),
      0x241: idef_RR("xor"),
      0x248: idef_RR("cgth"),
      0x249: idef_RR("eqv"),
      0x250: idef_RR("cgtb"),
      0x253: idef_RR("sumb"),
      0x258: idef_RR("hgt"),
      0x2a5: idef_R("clz"), # no first reg
      0x2a6: idef_R("xswd"), # no first reg
      0x2ae: idef_R("xshw"), # no first
      0x2b4: idef_R("cntb"), # no first reg
      0x2b6: idef_R("xsbh"), # no first reg
      0x2c0: idef_RR("clgt"),
      0x2c1: idef_RR("andc"),
      0x2c2: idef_RR("fcgt"),
      0x2c3: idef_RR("dfcgt"),
      0x2c4: idef_RR("fa"),
      0x2c5: idef_RR("fs"),
      0x2c6: idef_RR("fm"),
      0x2c8: idef_RR("clgth"),
      0x2c9: idef_RR("orc"),
      0x2ca: idef_RR("fcmgt"),
      0x2cb: idef_RR("dfcmgt"),
      0x2cc: idef_RR("dfa"),
      0x2cd: idef_RR("dfs"),
      0x2ce: idef_RR("dfm"),
      0x2d0: idef_RR("clgtb"),
      0x2d8: idef_RR("hlgt"), # false target
      0x340: idef_RR("addx"),
      0x341: idef_RR("sfx"),
      0x342: idef_RR("cgx"),
      0x343: idef_RR("bgx"),
      0x346: idef_RR("mpyhha"),
      0x34e: idef_RR("mpyhhau"),
      0x35c: idef_RR("dfma"),
      0x35d: idef_RR("dfms"),
      0x35e: idef_RR("dfnms"),
      0x35f: idef_RR("dfnma"),
      0x398: idef_R("fscrrd", noRA = True), # no first and second
      0x3b8: idef_R("fesd"),   # no first
      0x3b9: idef_R("frds"),   # no first
      0x3ba: idef_R("fscrwr"), # no first, rt is false target
      0x3c0: idef_RR("ceq"),
      0x3c2: idef_RR("fceq"),
      0x3c3: idef_RR("dfceq"),
      0x3c4: idef_RR("mpy"),
      0x3c5: idef_RR("mpyh"),
      0x3c7: idef_RR("mpys"),
      0x3c6: idef_RR("mpyhh"),
      0x3c8: idef_RR("ceqh"),
      0x3ca: idef_RR("fcmeq"),
      0x3cb: idef_RR("dfcmeq"),
      0x3cc: idef_RR("mpyu"),
      0x3ce: idef_RR("mpyhhu"),
      0x3d0: idef_RR("ceqb"),
      0x3d4: idef_RR("fi"),
      0x3d8: idef_RR("heq"), # rt is false target
    }

    # 4-bit opcodes (bits 0:3)
    self.itable_RRR = {
        0x8: idef_RRR("selb"),
        0xb: idef_RRR("shufb"),
        0xc: idef_RRR("mpya"),
        0xd: idef_RRR("fnms"),
        0xe: idef_RRR("fma"),
        0xf: idef_RRR("fms"),
    };

    self.itable_RI16 = {
      0x040: idef_RI16_rel("brz"),
      0x041: idef_RI16_abs("stqa", isBranch = False),
      0x042: idef_RI16_rel("brnz"),
      0x044: idef_RI16_rel("brhz"),
      0x046: idef_RI16_rel("brhnz"),
      0x047: idef_RI16_rel("stqr", isBranch = False),
      0x060: idef_RI16_abs("bra", noRA = True, flags = CF_STOP), # no RA
      0x061: idef_RI16_abs("lqa", isBranch = False),
      0x062: idef_RI16_abs("brasl", flags = CF_CALL),
      0x064: idef_RI16_rel("br", noRA = True, flags = CF_STOP),  # no RA
      0x065: idef_RI16("fsmbi"),
      0x066: idef_RI16_rel("brsl", flags = CF_CALL),
      0x067: idef_RI16_rel("lqr", isBranch = False),
      0x081: idef_RI16("il", signext = True),
      0x082: idef_RI16("ilhu"),
      0x083: idef_RI16("ilh"),
      0x0c1: idef_RI16("iohl"),
    }

    self.itable_RI7 = {
      0x078: idef_RI7("roti"),
      0x079: idef_RI7("rotmi"),
      0x07a: idef_RI7("rotmai"),
      0x07b: idef_RI7("shli"),
      0x07c: idef_RI7("rothi"),
      0x07d: idef_RI7("rothmi"),
      0x07e: idef_RI7("rotmahi"),
      0x1f4: idef_RI7_ls("cbd"),
      0x1f5: idef_RI7_ls("chd"),
      0x1f6: idef_RI7_ls("cwd"),
      0x1f7: idef_RI7_ls("cdd"),
      0x1f8: idef_RI7("rotqbii"),
      0x1f9: idef_RI7("rotqmbii"),
      0x1fb: idef_RI7("shlqbii"),
      0x1fc: idef_RI7("rotqbyi"),
      0x1fd: idef_RI7("rotqmbyi"),
      0x1ff: idef_RI7("shlqbyi"),
      0x3bf: idef_RI7("dftsv", signed = False),
    }

    self.itable_RI18 = {
      0x21: idef_RI18("ila"),
      0x08: idef_I16RO("hbra"), # roh/rol
      0x09: idef_I16RO("hbrr", rel = True), # roh/rol
    }

    # 10-bit opcodes (bits 0:9)
    self.itable_RI8 = {
      0x1d8: idef_RI8("cflts", 173),
      0x1d9: idef_RI8("cfltu", 173),
      0x1da: idef_RI8("csflt", 155),
      0x1db: idef_RI8("cuflt", 155),
    }

    self.itable = [None] * 2048

    for i in range(2048):
      opcode = i << 21
      RR = decode_RR(opcode)
      RRR = decode_RRR(opcode)
      RI7 = decode_RI7(opcode)
      RI8 = decode_RI8(opcode)
      RI10 = decode_RI10(opcode)
      RI16 = decode_RI16(opcode)
      RI18 = decode_RI18(opcode)

      ins = self.itable_RR.get(RR[0])
      ins = self.itable_RRR.get(RRR[0], ins)
      ins = self.itable_RI7.get(RI7[0], ins)
      ins = self.itable_RI8.get(RI8[0], ins)
      ins = self.itable_RI10.get(RI10[0], ins)
      ins = self.itable_RI16.get(RI16[0], ins)
      ins = self.itable_RI18.get(RI18[0], ins)

      if ins:
        self.itable[i] = ins

    # Now create an instruction table compatible with IDA processor module requirements
    Instructions = []
    i = 0
    for x in self.itable_RI10.values() + self.itable_RR.values() + \
      self.itable_RRR.values() + self.itable_RI16.values() + self.itable_RI7.values() + \
      self.itable_RI18.values() + self.itable_RI8.values():
        Instructions.append({'name': x.name, 'feature': x.cf})
        setattr(self, 'itype_' + x.name, i)
        i += 1

    # add simplified mnemonics
    Instructions.append({'name': "lr", 'feature': CF_CHG1 | CF_USE2})
    setattr(self, 'itype_lr', i)
    i += 1

    # icode of the last instruction + 1
    self.instruc_end = len(Instructions) + 1

    # Array of instructions
    self.instruc = Instructions

    # Icode of return instruction. It is ok to give any of possible return
    # instructions
    self.icode_return = self.itype_bi

    self.comments = {}
    for ins, cmt in spu_comments().items():
      nm = "itype_" + ins
      if hasattr(self, nm):
        self.comments[getattr(self, nm)] = cmt
      else:
        print "Warning: instruction %s not found" % ins

  # ----------------------------------------------------------------------
  def init_registers(self, gnunames = False):
    if gnunames:
      self.regNames = ["$%d" % d for d in range(0, 128)]
      self.regNames += ["$sp%d" % d for d in range(0, 128)]
      self.regNames += ["$ch%d" % d for d in range(0, 128)]
    else:
      self.regNames = [ "lr", "sp"] + ["r%d" % d for d in range(2, 128)]
      self.regNames += ["sp%d" % d for d in range(0, 128)]
      self.regNames += ["ch%d" % d for d in range(0, 128)]

    self.regNames  += ["CS", "DS"]

    if gnunames:
      for i in xrange(128):
        setattr(self, 'ireg_r%d'%i, i)
      for i in xrange(128, 256):
        setattr(self, 'ireg_sp%d' + (i-128), i)
      for i in xrange(256, 384):
        setattr(self, 'ireg_ch%d' + (i-256), i)
      setattr(self, 'ireg_lr', 0)
      setattr(self, 'ireg_sp', 1)
    else:
      for i in xrange(len(self.regNames)):
        setattr(self, 'ireg_' + self.regNames[i], i)
    self.regFirstSreg = self.ireg_CS
    self.regLastSreg  = self.ireg_DS

    # number of CS register
    self.regCodeSreg = self.ireg_CS

    # number of DS register
    self.regDataSreg = self.ireg_DS

  # ----------------------------------------------------------------------
  def notify_init(self, idp_file):
    # SPU is big endian
    idaapi.cvar.inf.mf = 1
    # init returns non-zero on success
    return 1

  # ----------------------------------------------------------------------
  def __init__(self):
    idaapi.processor_t.__init__(self)
    self.PTRSZ = 4 # Assume PTRSZ = 4 by default
    self.init_instructions()
    self.init_registers()

# ----------------------------------------------------------------------
def spu_comments():
  return {
    "a": "Add Word",
    "absdb": "Absolute Differences of Bytes",
    "addx": "Add Extended",
    "ah": "Add Halfword",
    "ahi": "Add Halfword Immediate",
    "ai": "Add Word Immediate",
    "and": "And",
    "andbi": "And Byte Immediate",
    "andc": "And with Complement",
    "andhi": "And Halfword Immediate",
    "andi": "And Word Immediate",
    "avgb": "Average Bytes",
    "bg": "Borrow Generate",
    "bgx": "Borrow Generate Extended",
    "bi": "Branch Indirect",
    "bihnz": "Branch Indirect If Not Zero Halfword",
    "bihz": "Branch Indirect If Zero Halfword",
    "binz": "Branch Indirect If Not Zero",
    "bisl": "Branch Indirect and Set Link",
    "bisled": "Branch Indirect and Set Link if External Data",
    "biz": "Branch Indirect If Zero",
    "br": "Branch Relative",
    "bra": "Branch Absolute",
    "brasl": "Branch Absolute and Set Link",
    "brhnz": "Branch If Not Zero Halfword",
    "brhz": "Branch If Zero Halfword",
    "brnz": "Branch If Not Zero Word",
    "brsl": "Branch Relative and Set Link",
    "brz": "Branch If Zero Word",
    "cbd": "Generate Controls for Byte Insertion (d-form)",
    "cbx": "Generate Controls for Byte Insertion (x-form)",
    "cdd": "Generate Controls for Doubleword Insertion (d-form)",
    "cdx": "Generate Controls for Doubleword Insertion (x-form)",
    "ceq": "Compare Equal Word",
    "ceqb": "Compare Equal Byte",
    "ceqbi": "Compare Equal Byte Immediate",
    "ceqh": "Compare Equal Halfword",
    "ceqhi": "Compare Equal Halfword Immediate",
    "ceqi": "Compare Equal Word Immediate",
    "cflts": "Convert Floating to Signed Integer",
    "cfltu": "Convert Floating to Unsigned Integer",
    "cg": "Carry Generate",
    "cgt": "Compare Greater Than Word",
    "cgtb": "Compare Greater Than Byte",
    "cgtbi": "Compare Greater Than Byte Immediate",
    "cgth": "Compare Greater Than Halfword",
    "cgthi": "Compare Greater Than Halfword Immediate",
    "cgti": "Compare Greater Than Word Immediate",
    "cgx": "Carry Generate Extended",
    "chd": "Generate Controls for Halfword Insertion (d-form)",
    "chx": "Generate Controls for Halfword Insertion (x-form)",
    "clgt": "Compare Logical Greater Than Word",
    "clgtb": "Compare Logical Greater Than Byte",
    "clgtbi": "Compare Logical Greater Than Byte Immediate",
    "clgth": "Compare Logical Greater Than Halfword",
    "clgthi": "Compare Logical Greater Than Halfword Immediate",
    "clgti": "Compare Logical Greater Than Word Immediate",
    "clz": "Count Leading Zeros",
    "cntb": "Count Ones in Bytes",
    "csflt": "Convert Signed Integer to Floating",
    "cuflt": "Convert Unsigned Integer to Floating",
    "cwd": "Generate Controls for Word Insertion (d-form)",
    "cwx": "Generate Controls for Word Insertion (x-form)",
    "dfa": "Double Floating Add",
    "dfceq": "Double Floating Compare Equal",
    "dfcgt": "Double Floating Compare Greater Than",
    "dfcmeq": "Double Floating Compare Magnitude Equal",
    "dfcmgt": "Double Floating Compare Magnitude Greater Than",
    "dfm": "Double Floating Multiply",
    "dfma": "Double Floating Multiply and Add",
    "dfms": "Double Floating Multiply and Subtract",
    "dfnma": "Double Floating Negative Multiply and Add",
    "dfnms": "Double Floating Multiply and Subtract",
    "dfs": "Double Floating Subtract",
    "dftsv": "Double Floating Test Special Value",
    "dsync": "Synchronize Data",
    "eqv": "Equivalent",
    "fa": "Floating Add",
    "fceq": "Floating Compare Equal",
    "fcgt": "Floating Compare Greater Than",
    "fcmeq": "Floating Compare Magnitude Equal",
    "fcmgt": "Floating Compare Magnitude Greater Than",
    "fesd": "Floating Extend Single to Double",
    "fi": "Floating Interpolate",
    "fm": "Floating Multiply",
    "fma": "Floating Multiply and Add",
    "fms": "Floating Multiply and Subtract",
    "fnms": "Floating Negative Multiply and Subtract",
    "frds": "Floating Round Double to Single",
    "frest": "Floating Reciprocal Estimate",
    "frsqest": "Floating Reciprocal Absolute Square Root Estimate",
    "fs": "Floating Subtract",
    "fscrrd": "Floating-Point Status and Control Register Write",
    "fscrwr": "Floating-Point Status and Control Register Read",
    "fsm": "Form Select Mask for Words",
    "fsmb": "Form Select Mask for Bytes",
    "fsmbi": "Form Select Mask for Bytes Immediate",
    "fsmh": "Form Select Mask for Halfwords",
    "gb": "Gather Bits from Words",
    "gbb": "Gather Bits from Bytes",
    "gbh": "Gather Bits from Halfwords",
    "hbr": "Hint for Branch (r-form)",
    "hbra": "Hint for Branch (a-form)",
    "hbrr": "Hint for Branch Relative",
    "heq": "Halt If Equal",
    "heqi": "Halt If Equal Immediate",
    "hgt": "Halt If Greater Than",
    "hgti": "Halt If Greater Than Immediate",
    "hlgt": "Halt If Logically Greater Than",
    "hlgti": "Halt If Logically Greater Than Immediate",
    "il": "Immediate Load Word",
    "ila": "Immediate Load Address",
    "ilh": "Immediate Load Halfword",
    "ilhu": "Immediate Load Halfword Upper",
    "iohl": "Immediate Or Halfword Lower",
    "iret": "Interrupt Return",
    "lnop": "No Operation (Load)",
    "lqa": "Load Quadword (a-form)",
    "lqd": "Load Quadword (d-form)",
    "lqr": "Load Quadword Instruction Relative (a-form)",
    "lqx": "Load Quadword (x-form)",
    "mfspr": "Move from Special-Purpose Register",
    "mpy": "Multiply",
    "mpya": "Multiply and Add",
    "mpyh": "Multiply High",
    "mpyhh": "Multiply High High",
    "mpyhha": "Multiply High High and Add",
    "mpyhhau": "Multiply High High Unsigned and Add",
    "mpyhhu": "Multiply High High Unsigned",
    "mpyi": "Multiply Immediate",
    "mpys": "Multiply and Shift Right",
    "mpyu": "Multiply Unsigned",
    "mpyui": "Multiply Unsigned Immediate",
    "mtspr": "Move to Special-Purpose Register",
    "nand": "Nand",
    "nop": "No Operation (Execute)",
    "nor": "Nor",
    "or": "Or",
    "orbi": "Or Byte Immediate",
    "orc": "Or with Complement",
    "orhi": "Or Halfword Immediate",
    "ori": "Or Word Immediate",
    "orx": "Or Across",
    "rchcnt": "Read Channel Count",
    "rdch": "Read Channel",
    "rot": "Rotate Word",
    "roth": "Rotate Halfword",
    "rothi": "Rotate Halfword Immediate",
    "rothm": "Rotate and Mask Halfword",
    "rothmi": "Rotate and Mask Halfword Immediate",
    "roti": "Rotate Word Immediate",
    "rotm": "Rotate and Mask Word",
    "rotma": "Rotate and Mask Algebraic Word",
    "rotmah": "Rotate and Mask Algebraic Halfword",
    "rotmahi": "Rotate and Mask Algebraic Halfword Immediate",
    "rotmai": "Rotate and Mask Algebraic Word Immediate",
    "rotmi": "Rotate and Mask Word Immediate",
    "rotqbi": "Rotate Quadword by Bits",
    "rotqbii": "Rotate Quadword by Bits Immediate",
    "rotqby": "Rotate Quadword by Bytes",
    "rotqbybi": "Rotate Quadword by Bytes from Bit Shift Count",
    "rotqbyi": "Rotate Quadword by Bytes Immediate",
    "rotqmbi": "Rotate and Mask Quadword by Bits",
    "rotqmbii": "Rotate and Mask Quadword by Bits Immediate",
    "rotqmby": "Rotate and Mask Quadword by Bytes",
    "rotqmbybi": "Rotate and Mask Quadword Bytes from Bit Shift Count",
    "rotqmbyi": "Rotate and Mask Quadword by Bytes Immediate",
    "selb": "Select Bits",
    "sf": "Subtract from Word",
    "sfh": "Subtract from Halfword",
    "sfhi": "Subtract from Halfword Immediate",
    "sfi": "Subtract from Word Immediate",
    "sfx": "Subtract from Extended",
    "shl": "Shift Left Word",
    "shlh": "Shift Left Halfword",
    "shlhi": "Shift Left Halfword Immediate",
    "shli": "Shift Left Word Immediate",
    "shlqbi": "Shift Left Quadword by Bits",
    "shlqbii": "Shift Left Quadword by Bits Immediate",
    "shlqby": "Shift Left Quadword by Bytes",
    "shlqbybi": "Shift Left Quadword by Bytes from Bit Shift Count",
    "shlqbyi": "Shift Left Quadword by Bytes Immediate",
    "shufb": "Shuffle Bytes",
    "stop": "Stop and Signal",
    "stopd": "Stop and Signal with Dependencies",
    "stqa": "Store Quadword (a-form)",
    "stqd": "Store Quadword (d-form)",
    "stqr": "Store Quadword Instruction Relative (a-form)",
    "stqx": "Store Quadword (x-form)",
    "sumb": "Sum Bytes into Halfwords",
    "sync": "Synchronize",
    "wrch": "Write Channel",
    "xor": "Exclusive Or",
    "xorbi": "Exclusive Or Byte Immediate",
    "xorhi": "Exclusive Or Halfword Immediate",
    "xori": "Exclusive Or Word Immediate",
    "xsbh": "Extend Sign Byte to Halfword",
    "xshw": "Extend Sign Halfword to Word",
    "xswd": "Extend Sign Word to Doubleword",
  }

# ----------------------------------------------------------------------
def PROCESSOR_ENTRY():
  return spu_processor_t()
