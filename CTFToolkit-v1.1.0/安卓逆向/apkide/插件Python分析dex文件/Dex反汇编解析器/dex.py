import sys
import struct
import array
from leb128 import *
from dex_ints import *
DEX_MAGIC = "dex\n"
DEX_OPT_MAGIC = "dey\n"

class dex_encode_field:
	def __init__(self,idx,flags):
		self.m_field_idx_diff = idx
		self.m_access_flags = flags
	def printf(self,dex_object):
		name = dex_object.gettypenamebyid(self.m_field_idx_diff)
		#print "%-20s%08x %s"%("field_idx_diff",self.m_field_idx_diff,name)	
		flags = dex_object.get_access_flags(self.m_access_flags)
		#print "%-20s%08x %s"%("access_flags",self.m_access_flags,flags)			
		print "%s "%flags,
		dex_object.FieldId_list[self.m_field_idx_diff].printf_l(dex_object)

class method_code:
	def __init__(self,dex_object,offset):
		format = "H"
		self.registers_size, = struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.ins_size,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.outs_size,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.tries_size,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		format = "I"
		self.debug_info_off,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.insns_size,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.insns = offset
		offset += 2*self.insns_size
		if self.insns_size %2 ==1:
			offset+=2
		if self.tries_size == 0:
			self.tries = 0 
			self.handlers = 0
		else:
			self.tries = offset 
			self.handlers = offset + self.tries_size * struct.calcsize("I2H")
	def get_param_list(self,dex_object):
		if self.debug_info_off != 0:
			return parse_debug_info_method_parameter_list(dex_object,self.debug_info_off)
		return []
	def printf(self,dex_object,prefix=""):
		
		print "%s%-20s:%08x:%10d"%(prefix,"registers_size",self.registers_size,self.registers_size)
		print "%s%-20s:%08x:%10d"%(prefix,"insns_size",self.insns_size,self.insns_size)
		print "%s%-20s:%08x:%10d"%(prefix,"debug_info_off",self.debug_info_off,self.debug_info_off)
		print "%s%-20s:%08x:%10d"%(prefix,"ins_size",self.ins_size,self.ins_size)
		print "%s%-20s:%08x:%10d"%(prefix,"outs_size",self.outs_size,self.outs_size)
		print "%s%-20s:%08x:%10d"%(prefix,"tries_size",self.tries_size,self.tries_size)
		print "%s%-20s:%08x:%10d"%(prefix,"insns",self.insns,self.insns)
		print "%s%-20s:%08x:%10d"%(prefix,"tries",self.tries,self.tries)
		print "%s%-20s:%08x:%10d"%(prefix,"handlers",self.handlers,self.handlers)

		parse_instruction(dex_object.m_content[self.insns:self.insns+self.insns_size*2],self.insns,dex_object)
		if self.debug_info_off != 0:
			parse_debug_info(dex_object,self.debug_info_off)
		
		
class dex_encode_method:
	def __init__(self,idx,flags,code_off,dex_object):
		self.m_method_idx_diff = idx
		self.m_access_flags = flags
		self.m_code_off = code_off
		if code_off:
			self.m_code_item = method_code(dex_object,code_off)#dex_object.m_content[code_off:])
	def printf(self,dex_object):
		name = dex_object.gettypenamebyid(self.m_method_idx_diff)
		print "%-20s%08x %s"%("m_method_idx_diff",self.m_method_idx_diff,name)	
		flags = dex_object.get_access_flags(self.m_access_flags)
		print "%-20s%08x %s"%("access_flags",self.m_access_flags,flags)	
		print "%-20s%08x %d"%("code_off",self.m_code_off,self.m_code_off)	
		if self.m_code_off !=0:
			self.m_code_item.printf(dex_object)
	def printf_l(self,dex_object,is_virtual):
		flags = dex_object.get_access_flags(self.m_access_flags)
		if is_virtual:
			flags += " virtual"
		print "%48s"%flags,
		dex_object.MethodId_list[self.m_method_idx_diff].printf(dex_object)
		if self.m_code_off!=0:	
			self.m_code_item.printf(dex_object)
		

class dex_class:
	def __init__(self,dex_object,classid):
		if classid >= dex_object.m_classDefSize:
			return ""
		offset = dex_object.m_classDefOffset + classid * struct.calcsize("8I")
		self.offset = offset
		format = "I"
		self.thisClass,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.modifiers,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.superClass,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.interfacesOff,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.sourceFileIdx,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.annotationsOff,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.classDataOff,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.staticValuesOff,=struct.unpack_from(format,dex_object.m_content,offset)
		offset += struct.calcsize(format)
		self.index = classid
		self.interfacesSize = 0
		if self.interfacesOff != 0:
			self.interfacesSize, = struct.unpack_from("I",dex_object.m_content,self.interfacesOff)
		if self.classDataOff != 0:
			offset = self.classDataOff
			count,self.numStaticFields = get_uleb128(dex_object.m_content[offset:])
			offset += count
			count,self.numInstanceFields = get_uleb128(dex_object.m_content[offset:])
			offset += count
			count,self.numDirectMethods = get_uleb128(dex_object.m_content[offset:])
			offset += count
			count,self.numVirtualMethods = get_uleb128(dex_object.m_content[offset:])	
		else:
			self.numStaticFields = 0
			self.numInstanceFields = 0
			self.numDirectMethods = 0
			self.numVirtualMethods = 0
	def format_classname(self,name):
		name = name[1:-1].replace("/","_")
		name = name.replace("$","_")
		return name
	def create_header_file_for_cplusplus(self,dex_object):
		typelist = []
		name = self.format_classname(dex_object.gettypename(self.thisClass))
		f = open(name+".h","w")
		str1 =  "class %s"%name
		supername = dex_object.gettypename(self.superClass)

		if dex_object.m_class_name_id.has_key(supername) :
			str1 += " : "
			supername = dex_object.gettypename(self.superClass)
			str1 += self.format_classname(supername)
		str1 += "\n{\n"
		offset = self.classDataOff
		n,tmp = get_uleb128(dex_object.m_content[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.m_content[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.m_content[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.m_content[offset:offset+5])
		offset += n
		field_idx=0
		prev_access = -1
		for i in xrange(0,self.numStaticFields):
			n,field_idx_diff = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			field_idx+=field_idx_diff

			n,modifiers = get_uleb128(dex_object.m_content[offset:offset+5])
			
			access_str,cur_access = dex_object.get_access_flags1(modifiers)		
			if cur_access != prev_access:
				str1 += access_str
				str1 += "\n"
				prev_access = cur_access
			str1 += "\tconst "
			str1 += dex_object.getfieldfullname1(field_idx)
			if field_idx not in typelist:
				typelist.append(field_idx)
			offset += n		
			if self.staticValuesOff:
				str1 += " = "
				staticoffset=get_static_offset(dex_object.m_content[self.staticValuesOff:],i)
				if staticoffset == -1:
					str1 += "0;\n"
					continue
				size,str2 = parse_encoded_value1(dex_object,dex_object.m_content[self.staticValuesOff+staticoffset:])
				str1 += str2
			str1 += ";\n"	
		field_idx=0
		str1+="////////////////////////////////////////////////////////\n"
		for i in xrange(0,self.numInstanceFields):
			n,field_idx_diff = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			field_idx+=field_idx_diff
			n,modifiers = get_uleb128(dex_object.m_content[offset:offset+5])
			access_str,cur_access = dex_object.get_access_flags1(modifiers)		
			if cur_access != prev_access:
				str1 += access_str
				str1 += "\n"
				prev_access = cur_access
			str1 += "\t"
			str1 += dex_object.getfieldfullname1(field_idx)
			if field_idx not in typelist:
				typelist.append(field_idx)
			str1 += ";\n"	
			offset += n			
		#print str1
		method_idx = 0
		prev_access = -1
		for i in xrange(0,self.numDirectMethods):	
			n,method_idx_diff = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			n,access_flags = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			n,code_off = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			method_idx += method_idx_diff
			access_str,cur_access = dex_object.get_access_flags1(access_flags)		
			if cur_access != prev_access:
				str1 += access_str
				str1 += "\n"
				prev_access = cur_access			
			str1 += "\t"
			parameter_list=[]
			if code_off != 0:
				parameter_list = method_code(dex_object,code_off).get_param_list(dex_object)
			str1 += dex_object.getmethodfullname1(method_idx,parameter_list,True)
			#print "%s           codeoff=%x"%(dex_object.getmethodname(method_idx),code_off)
			str1 += ";\n"
		method_idx = 0
		str1+="//////////////////////virtual method//////////////////////////////////\n"
		for i in xrange(0,self.numVirtualMethods):			
			n,method_idx_diff = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			n,access_flags = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			n,code_off = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			method_idx += method_idx_diff
			access_str,cur_access = dex_object.get_access_flags1(access_flags)		
			if cur_access != prev_access:
				str1 += access_str
				str1 += "\n"
				prev_access = cur_access			
			str1 +="\tvirtual "
			parameter_list=[]
			if code_off != 0:
				parameter_list = method_code(dex_object,code_off).get_param_list(dex_object)
			str1 += dex_object.getmethodfullname1(method_idx,parameter_list,True)							
			str1 += ";\n"
		str1 += "}"
		#print str1
		f.write(str1)
		f.close()
		return typelist
	def printf(self,dex_object):
		#if dex_object.gettypename(self.thisClass)!="Landroid/Manifest$permission;":
		#	return
		print "%-20s:%08x:%10d  %s"%("thisClass",self.thisClass,self.thisClass,dex_object.gettypename(self.thisClass))
		print "%-20s:%08x:%10d  %s"%("superClass",self.superClass,self.superClass,dex_object.gettypename(self.superClass))
		print "%-20s:%08x:%10d"%("modifiers",self.modifiers,self.modifiers)
		print "%-20s:%08x:%10d"%("offset",self.offset,self.offset)
		print "%-20s:%08x:%10d"%("annotationsOff",self.annotationsOff,self.annotationsOff)
		print "%-20s:%08x:%10d"%("numStaticFields",self.numStaticFields,self.numStaticFields)
		print "%-20s:%08x:%10d"%("numInstanceFields",self.numInstanceFields,self.numInstanceFields)
		print "%-20s:%08x:%10d"%("numDirectMethods",self.numDirectMethods,self.numDirectMethods)
		print "%-20s:%08x:%10d"%("numVirtualMethods",self.numVirtualMethods,self.numVirtualMethods)
		print "%-20s:%08x:%10d"%("classDataOff",self.classDataOff,self.classDataOff)
		print "%-20s:%08x:%10d"%("interfacesOff",self.interfacesOff,self.interfacesOff)
		print "%-20s:%08x:%10d"%("interfacesSize",self.interfacesSize,self.interfacesSize)
		offset = self.interfacesOff + struct.calcsize("I")
		for n in xrange(0,self.interfacesSize):
			typeid, = struct.unpack_from("H",dex_object.m_content,offset)
			offset += struct.calcsize("H")
			print "\t\t"+ dex_object.gettypename(typeid)

		print "%-20s:%08x:%10d"%("staticValuesOff",self.staticValuesOff,self.staticValuesOff)
		print "%-20s:%08x:%10d  %s"%("sourceFileIdx",self.sourceFileIdx,self.sourceFileIdx,dex_object.getstringbyid(self.sourceFileIdx))
		offset = self.classDataOff
		n,tmp = get_uleb128(dex_object.m_content[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.m_content[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.m_content[offset:offset+5])
		offset += n
		n,tmp = get_uleb128(dex_object.m_content[offset:offset+5])
		offset += n
		field_idx=0
		for i in xrange(0,self.numStaticFields):
			n,field_idx_diff = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			field_idx+=field_idx_diff
			print dex_object.getfieldfullname(field_idx),
			n,modifiers = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			if self.staticValuesOff:
				staticoffset=get_static_offset(dex_object.m_content[self.staticValuesOff:],i)
				if staticoffset == -1:
					print "0;"
					continue
				parse_encoded_value(dex_object,dex_object.m_content[self.staticValuesOff+staticoffset:])
			print ""

		field_idx=0
		for i in xrange(0,self.numInstanceFields):
			n,field_idx_diff = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			field_idx+=field_idx_diff
			print dex_object.getfieldfullname(field_idx)
			n,modifiers = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n		

		print "=========numDirectMethods[%d]=numVirtualMethods[%d]=numStaticMethods[0]========="%(self.numDirectMethods,self.numVirtualMethods)
		method_idx = 0
		for i in xrange(0,self.numDirectMethods):	
			n,method_idx_diff = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			n,access_flags = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			n,code_off = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			method_idx += method_idx_diff
			print dex_object.getmethodfullname(method_idx,True)
			#print "%s           codeoff=%x"%(dex_object.getmethodname(method_idx),code_off)
			if code_off != 0:
				
				method_code(dex_object,code_off).printf(dex_object,"\t\t")
		method_idx = 0
		for i in xrange(0,self.numVirtualMethods):			
			n,method_idx_diff = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			n,access_flags = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			n,code_off = get_uleb128(dex_object.m_content[offset:offset+5])
			offset += n
			method_idx += method_idx_diff
			print dex_object.getmethodfullname(method_idx,True)
			#print "%s           codeoff=%x"%(dex_object.getmethodname(method_idx),code_off)
			if code_off != 0:
				method_code(dex_object,code_off).printf(dex_object,"\t\t")

		print "================================================================================"
		if self.annotationsOff != 0:
			offset = self.annotationsOff
			self.class_annotations_off,self.fields_size,self.annotated_methods_size,self.annotated_parameters_size,=struct.unpack_from("4I",dex_object.m_content,offset)
			#print "%-30s:%08x:%09d"%("class_annotations_off",self.class_annotations_off,self.class_annotations_off)
			#print "%-30s:%08x:%09d"%("fields_size",self.fields_size,self.fields_size)
			#print "%-30s:%08x:%09d"%("annotated_methods_size",self.annotated_methods_size,self.annotated_methods_size)
			#print "%-30s:%08x:%09d"%("annotated_parameters_size",self.annotated_parameters_size,self.annotated_parameters_size)
			offset =  self.annotationsOff + struct.calcsize("4I")
			
			if self.fields_size:
				for  i in xrange(0,self.fields_size):
					field_idx,annotations_off,=struct.unpack_from("2I",dex_object.m_content,offset)
					offset += struct.calcsize("2I")
					print dex_object.getfieldname(field_idx),
					parse_annotation_set_item(dex_object,annotations_off)
			
			if self.annotated_methods_size:
				print "=====annotated_methods_size=====    offset=[%x]===="%offset
				for  i in xrange(0,self.annotated_methods_size):
					method_idx,annotations_off,=struct.unpack_from("2I",dex_object.m_content,offset)
					offset += struct.calcsize("2I")
					print dex_object.getmethodname(method_idx),
					parse_annotation_set_item(dex_object,annotations_off)
			if self.annotated_parameters_size:
				for  i in xrange(0,self.annotated_parameters_size):
					method_idx,annotations_off,=struct.unpack_from("2I",dex_object.m_content,offset)
					offset+=struct.calcsize("2I")
					print dex_object.getmethodname(method_idx),
					parse_annotation_set_ref_list(dex_object,annotations_off)
			if self.class_annotations_off == 0:
				return
			print "self.class_annotations_off = %x"%self.class_annotations_off
			parse_annotation_set_item(dex_object,self.class_annotations_off)

def get_static_offset(content,index):
	offset = 0
	m,size =  get_uleb128(content[offset:offset+5])
	if index >= size:
		return -1
	offset += m
	for i in xrange(0,index):
		offset += get_encoded_value_size(content[offset:])
	return offset


def get_encoded_value_size(content):
	offset = 0
	arg_type, = struct.unpack_from("B",content,offset)
	offset+=struct.calcsize("B")
	value_arg = arg_type>>5
	value_type = arg_type &0x1f
	if value_type in [0x2,3,4,6,0x10,0x11,0x17,0x18,0x19,0x1a,0x1b]:
		offset += (value_arg+1)
	elif value_type == 0:
		offset += 1
	elif value_type == 0x1e or value_type == 0x1f:
		offset += 0
	elif value_type == 0x1d:
		offset += get_encoded_annotation_size(content[offset:])
	elif value_type == 0x1c:
		m,asize = get_uleb128(m_content[offset:offset+5])
		offset += m
		for q in xrange(0,asize):
			offset += get_encoded_value_size(content[offset:])
	else:
		print "***************error parse encode_value**************"
	return offset


class field_annotation:
	def __init__(self,content):
		self.field_idx,self.annotations_off, = struct.unpack_from("2I",content)
			
class annotations_directory_item:
	def __init__(self,content,dex_object):
		self.class_annotations_off,self.fields_size,self.annotated_methods_size,self.annotated_parameters_size , =struct.unpack_from("4I",content)
		self.m_fields_list = []
		self.m_methods_list = []
		self.m_parameters_list = []
		offset = struct.calcsize("4I")
		if self.fields_size:
			self.m_fields_list = array.array("L")
			self.m_fields_list.fromstring(content[offset:offset+8*self.fields_size])
		offset = offset+4*self.fields_size
		if self.annotated_methods_size:
			self.m_methods_list = array.array("L")
			self.m_methods_list.fromstring(content[offset:offset+8*self.annotated_methods_size])
		offset = offset + 4*self.annotated_methods_size
		for i in xrange(0,annotated_methods_size):
			self.m_parameters_list = array.array("L")
			self.m_parameters_list.fromstring(content[offset:offset+8*self.annotated_parameters_size])
		content = dex_object.m_content
		for i in xrange(0,self.fields_size):
			size = self.m_fields_list[i*2]						
			offset = self.m_fields_list[i*2+1]
			of = array.array("L")
			of.fromstring(content[offset:offset+4*size])
			for off in of:
				visibility = content[off]
				off += 1
				k,type_idx = get_uleb128(content[off:])
				off += k
				k,size = get_uleb128(content[off:])
				for m in xrange(0,size):
					off += k
					k,name_idx=get_uleb128(content[off:])
					off += k
					get_encoded_value(content[off:])

def parse_debug_info_method_parameter_list(dex_object,offset):
	parameter_list = []
	n ,current_line = get_uleb128(dex_object.m_content[offset:offset+5])
	offset += n
	n,parameters_size = get_uleb128(dex_object.m_content[offset:offset+5])
	offset += n
	for i in xrange(0,parameters_size):
		n,string_idx = get_uleb128p1(dex_object.m_content[offset:offset+5])
		if string_idx!=-1:
			parameter_list.append(dex_object.getstringbyid(string_idx))
		offset+=n
	return 	parameter_list
def parse_debug_info(lex_object,offset):
	print "===parse_debug_info====offset = %08x"%offset
	n ,current_line = get_uleb128(lex_object.m_content[offset:offset+5])
	offset += n
	n,parameters_size = get_uleb128(lex_object.m_content[offset:offset+5])
	offset += n
	for i in xrange(0,parameters_size):
		n,string_idx = get_uleb128p1(lex_object.m_content[offset:offset+5])
		if string_idx!=-1:
			print lex_object.getstringbyid(string_idx)
		offset+=n
	start = offset
	current_pc = 0
	print "===opcode====offset = %08x  line=%d pc=%d"%(offset,current_line,current_pc)


	totalsize = len(lex_object.m_content)
	while offset < totalsize:
		#bytecode = struct.unpack_from("B",lex_object.m_content,offset)
		bytecode = ord(lex_object.m_content[offset])
		offset += 1
		print "opcode[%02x]"%bytecode,
		if bytecode == 0:
			print ""
			break
		elif bytecode == 1:
			n,val = get_uleb128(lex_object.m_content[offset:offset+5])
			current_pc += val;
			offset += n
			print "line=%d  pc=%x"%(current_line,current_pc)
		elif bytecode == 2:
			n,val = get_leb128(lex_object.m_content[offset:offset+5])
			
			current_line += val       
			offset += n
			print "line=%d  pc=%x   val=%08x(%d)"%(current_line,current_pc,val,val)
		elif bytecode == 3:
			n,register_num = get_uleb128(lex_object.m_content[offset:offset+5])
			offset += n
			n,name_idx = get_uleb128p1(lex_object.m_content[offset:offset+5])
			offset += n
			n,type_idx = get_uleb128p1(lex_object.m_content[offset:offset+5])
			offset += n
			print "v%d %s %s  START_LOCAL"%(register_num,lex_object.gettypenamebyid(type_idx),lex_object.getstringbyid(name_idx))
		elif bytecode == 4:
			n,register_num = get_uleb128(lex_object.m_content[offset:offset+5])
			offset += n
			n,name_idx = get_uleb128p1(lex_object.m_content[offset:offset+5])
			offset += n
			n,type_idx = get_uleb128p1(lex_object.m_content[offset:offset+5])
			offset += n
			n,sig_idx = get_uleb128p1(lex_object.m_content[offset:offset+5])
			offset += n
			print "v%d %s %s   START_LOCAL_EXTENDED"%(register_num,lex_object.gettypenamebyid(type_idx),lex_object.getstringbyid(name_idx))
		elif bytecode == 5:
			n,register_num = get_uleb128(lex_object.m_content[offset:offset+5])
			offset += n
			print "v%d  END_LOCAL"%register_num
		elif bytecode == 6:
			n,register_num = get_uleb128(lex_object.m_content[offset:offset+5])
			offset += n
			print "v%d   register to restart"%register_num
		elif bytecode == 7:
			print "SET_PROLOGUE_END"
			pass
		elif bytecode == 8:
			print "SET_EPILOGUE_BEGIN"
			pass
		elif bytecode == 9:
			n,name_idx = get_uleb128(lex_object.m_content[offset:offset+5])
			print "%s"%lex_object.getstringbyid(name_idx)
			offset += n
		else:
			adjusted_opcode = bytecode - 0xa
			current_line +=  (adjusted_opcode % 15)-4
			current_pc += (adjusted_opcode / 15)
			#offset += 1
			print "line=%d  pc=%x  adjusted_opcode=%d  pc+ %d  line+%d"%(current_line,current_pc,adjusted_opcode,(adjusted_opcode/15),(adjusted_opcode%15)-4)
	print "===parse_debug_info====offset = %08x$"%offset
def get_encoded_value(content):
	
	VALUE_SHORT = 0x2
	VALUE_CHAR = 0x3
	VALUE_INT = 0x4
	VALUE_LONG = 0x6
	VALUE_FLOAT = 0x10
	VALUE_DOUBLE = 0x11
	VALUE_STRING = 0x17
	VALUE_TYPE = 0x18
	VALUE_FIELD = 0x19
	VALUE_METHOD = 0x1a
	VALUE_ENUM = 0x1b
	VALUE_ARRAY = 0x1c
	VALUE_ANNOTATION = 0x1d
	VALUE_NULL = 0x1e
	VALUE_BOOLEAN = 0x1f
	type_enum = [0x0,0x2,0x3,0x4,0x6,0x10,0x11,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f]
	size_type = ord(content[0])
	usebyte = 1
	
	size = size_type >> 5
	type = size_type & 0x1f
	if type not in size_type:
		print "encoded value error!"
	if type == 0 and size == 0:
		value,=struct.unpack_from("b",content,1)
		usebyte += 1

	elif type == VALUE_SHORT:
		if size == 0:
			value,=struct.unpack_from("b",content,1)
		elif size == 1:
			value,=struct.unpack_from("h",content,1)
		else:
			print "encoded value error! type=short type=%d size=%d"%(type,size)
		usebyte+=size+1
	elif type == VALUE_CHAR:
		if size == 0:
			value, = struct.unpack_from("B",content,1)
		elif size == 1:
			value, = struct.unpack_from("H",content,1)
		else:
			print "encoded value error! type=char type=%d size=%d"%(type,size)
		usebyte+=size+1
	elif type == VALUE_INT:
		if size == 0:
			value,=struct.unpack_from("b",content,1)
		elif size == 1:
			value,=struct.unpack_from("h",content,1)
		elif size == 2:
			value = 0
		elif size == 3:
			value,=struct.unpack_from("i",content,1)
		else:
			print "encoded value error! type=int type=%d size=%d"%(type,size)
		usebyte+=size+1
	
	elif type == VALUE_LONG:
		if size > 7:
			print "encoded value error! type=long type=%d size=%d"%(type,size)
		value=content[1:1+size+1]
		usebyte+=size+1
	elif type == VALUE_FLOAT:
		if size > 3:
			print "encoded value error! type=float type=%d size=%d"%(type,size)
		value=content[1:1+size+1]
		usebyte+=size+1
	elif type == VALUE_DOUBLE:
		if size > 7:
			print "encoded value error! type=double type=%d size=%d"%(type,size)
		value = content[1:1+size+1]
		usebyte+=size+1
		
	elif type == VALUE_STRING:
		if size > 3:
			print "encoded value error! type=double type=%d size=%d"%(type,size)
		value = content[1:1+size+1]
		usebyte+=size+1
	elif type == VALUE_TYPE:
		if size > 3:
			print "encoded value error! type=type type=%d size=%d"%(type,size)
		value = content[1:1+size+1]
		usebyte+=size+1
		
	elif type == VALUE_FIELD:
		if size > 3:
			print "encoded value error! type=field type=%d size=%d"%(type,size)
		value = content[1:1+size+1]
		usebyte+=size+1
	elif type == VALUE_METHOD:
		if size > 3:
			print "encoded value error! type=medhod type=%d size=%d"%(type,size)
		value = content[1:1+size+1]
		usebyte+=size+1
	elif type == VALUE_ENUM:
		if size > 3:
			print "encoded value error! type=enum type=%d size=%d"%(type,size)
		value = content[1:1+size+1]
		usebyte+=size+1
	elif type == VALUE_ARRAY:
		if size != 0:
			print "encoded value error! type=encoded_array type=%d size=%d"%(type,size)
		k,value=get_encoded_array(content[1:1+size+1])
		usebyte+=k
	elif type == VALUE_ANNOTATION:
		if size != 0:
			print "encoded value error! type=encoded_annotation type=%d size=%d"%(type,size)
		k,type_idx = get_uleb128(content[1:])
		k1,s = get_uleb128(content[1+k:])
		k1 = 1+k+k1
		for n in xrange(0,s):
			k2,name_index = get_uleb128(content[k1:])
			k1+=k2
			k3,value = get_encoded_value(content[k1:])
			k1+=k3
		usebyte+=k1
	elif type == VALUE_NULL:
		if size != 0:
			print "encoded value error! type=NULL  type=%d size=%d"%(type,size)
		value="NULL"
	elif type == VALUE_BOOLEAN:
		value = size
	return usebyte,value

def get_encoded_array(content):
	offset,size = get_uleb128(content)
	userbyte = offset
	for i in xrange(0,size):
		off,value = get_encoded_value(content[offset:])
		offset += off
		userbyte += off
	return userbyte,value
		
def get_encoded_array_by_index(content,index):
	offset,size = get_uleb128(content)
	userbyte = offset
	for i in xrange(0,size):
		off,value = get_encoded_value(content[offset:])
		offset += off
		userbyte+=off
		if index == i:
			return userbyte,value
	return offset
		
class annotations_directory_item:
	def __init__(self,content):
		self.m_class_annotations_off,self.m_fields_size,self.m_annotated_methods_size,self.m_annotated_parameters_size,=struct.unpack_from("4I",content)
		pass

def shorty_decode(name):
	val = {"V":"void",
		"Z":"boolean",
		"B":"byte",
		"S":"short",
		"C":"char",
		"I":"int",
		"J":"long",
		"F":"float",
		"D":"double",
		"L":"L"
		}
	value = ""

	if name[-1] == ';':
		if name[0] == 'L':
			return name[1:-1].replace("/",".")
		if name[0]=='[':
			if name[1] == 'L':
				return name[2:-1].replace("/",".")+"[]"
			else:
				return name[1:-1].replace("/",".")+"[]"
	i = 0
	for ch in name:
		if val.has_key(ch):
			if i != 0:
				value += " | "
			value += val[ch]
			i += 1
	if '[' in name:
		value += "[]"
	return value

def get_encoded_value_size(content):
	offset = 0
	arg_type, = struct.unpack_from("B",content,offset)
	offset+=struct.calcsize("B")
	value_arg = arg_type>>5
	value_type = arg_type &0x1f
	if value_type in [0x2,3,4,6,0x10,0x11,0x17,0x18,0x19,0x1a,0x1b]:
		offset += (value_arg+1)
	elif value_type == 0:
		offset += 1
	elif value_type == 0x1e or value_type == 0x1f:
		offset += 0
	elif value_type == 0x1d:
		offset += get_encoded_annotation_size(content[offset:])
	elif value_type == 0x1c:
		m,asize = get_uleb128(m_content[offset:5+offset])
		offset += m
		for q in xrange(0,asize):
			offset += get_encoded_value_size(content[offset:])
	else:
		print "***************error parse encode_value**************"
	return offset

def get_encoded_annotation_size(content):
	offset = 0
	n ,type_idx = get_uleb128(content[offset:5+offset])
	offset += n
	n ,size = get_uleb128(content[offset:5+offset])
	offset += n
	for i in xrange(0,n):
		n ,name_idx = get_uleb128(content[offset:5+offset])
		offset += n
		offset += get_encoded_value_size(content[offset:])
	return offset
def parse_encoded_value(lex_object,content,is_root=False):
	offset = 0
	arg_type, = struct.unpack_from("B",content,offset)
	offset+=struct.calcsize("B")
	value_arg = arg_type>>5
	value_type = arg_type &0x1f
	if value_type in [0x2,3,4,6,0x10,0x11,0x17,0x18,0x19,0x1a,0x1b]:
		sum = 0
		for q in xrange(0,value_arg+1):
			mm = ord(content[offset+q])
			mm <<= 8*q
			sum|=mm
			#sum += ord(content[offset+q])
		if value_type == 0x17:
			print "string@%d"%sum,
			print lex_object.getstringbyid(sum),
		elif value_type == 0x18:
			print "type@%d"%sum,
			print lex_object.gettypename(sum),
		elif value_type == 0x19:
			print "field@%d"%sum,
			print lex_object.getfieldname(sum),
		elif value_type == 0x1a:
			print "method@%d"%sum,
			print lex_object.getmethodname(sum),
		else:
			str = ""
			for q in xrange(0,value_arg+1):
				str += "%02x "%(ord(content[offset+q]))
			print str,
		offset += (value_arg+1)
	elif value_type == 0:
		print "%02x"%ord(content[offset]),
		offset += 1

	elif value_type == 0x1e :
		print "NULL",
	elif value_type == 0x1f:
		if value_arg == 0:
			print "False",
		else:
			print "True",
		offset += 0
	elif value_type == 0x1d:
		offset += parse_encoded_annotation(lex_object,content[offset:])
	elif value_type == 0x1c:
		m,asize = get_uleb128(content[offset:5])
		offset += m
		print "[%d]"%asize,
		for q in xrange(0,asize):
			offset += parse_encoded_value(lex_object,content[offset:],False)
	else:
		print "***************error parse encode_value**************"
	return offset

def parse_encoded_value1(lex_object,content,is_root=False):
	str1 = ""
	offset = 0
	arg_type, = struct.unpack_from("B",content,offset)
	offset+=struct.calcsize("B")
	value_arg = arg_type>>5
	value_type = arg_type &0x1f
	if value_type in [0x2,3,4,6,0x10,0x11,0x17,0x18,0x19,0x1a,0x1b]:
		sum = 0
		for q in xrange(0,value_arg+1):
			mm = ord(content[offset+q])
			mm <<= 8*q
			sum|=mm
			#sum += ord(content[offset+q])
		if value_type == 0x17:
			str1 += "\""
			str1 += lex_object.getstringbyid(sum)
			str1 += "\""
		elif value_type == 0x18:
			print "type@%d"%sum,
			str1 += lex_object.gettypename(sum),
		elif value_type == 0x19:
			print "field@%d"%sum,
			str1 += lex_object.getfieldname(sum),
		elif value_type == 0x1a:
			print "method@%d"%sum,
			str1 += lex_object.getmethodname(sum),
		else:
			str2 = ""
			for q in xrange(0,value_arg+1):
				str2 += "%02x "%(ord(content[offset+q]))
			str1+= str2
		offset += (value_arg+1)
	elif value_type == 0:
		str1 += "%02x"%ord(content[offset])
		offset += 1

	elif value_type == 0x1e :
		str1 += "NULL"
	elif value_type == 0x1f:
		if value_arg == 0:
			str1 += "false"
		else:
			str1 += "true"
		offset += 0
	elif value_type == 0x1d:
		size ,text = parse_encoded_annotation1(lex_object,content[offset:])
		offset += size
		str1 += text
	elif value_type == 0x1c:
		m,asize = get_uleb128(content[offset:5])
		offset += m
		str1 += "[%d]"%asize
		for q in xrange(0,asize):
			size,text = parse_encoded_value1(lex_object,content[offset:],False)
			offset += size
			str1 += text
	else:
		str1 += "***************error parse encode_value**************"
	return offset,str1
	
def parse_encoded_value4441(lex_object,content,is_root=False):
	offset = 0
	arg_type, = struct.unpack_from("B",content,offset)
	offset+=struct.calcsize("B")
	value_arg = arg_type>>5
	value_type = arg_type &0x1f
	if value_type in [0x2,3,4,6,0x10,0x11,0x17,0x18,0x19,0x1a,0x1b]:
		str = ""
		for q in xrange(0,value_arg+1):
			str += "%02x "%(ord(content[offset+q]))
		print str,
		offset += (value_arg+1)
	elif value_type == 0:
		print "%02x"%ord(content[offset]),
		offset += 1

	elif value_type == 0x1e :
		print "NULL",
	elif value_type == 0x1f:
		if value_arg == 0:
			print "False",
		else:
			print "True",
		offset += 0
	elif value_type == 0x1d:
		offset += parse_encoded_annotation(lex_object,content[offset:])
	elif value_type == 0x1c:
		m,asize = get_uleb128(content[offset:5+offset])
		offset += m
		print "[%d]"%asize,
		for q in xrange(0,asize):
			offset += parse_encoded_value(lex_object,content[offset:],False)
	else:
		print "***************error parse encode_value**************"
	return offset
def parse_encoded_annotation1(lex_object,content,is_root=False):
	str1 = ""
	offset = 0
	n ,type_idx = get_uleb128(content[offset:5+offset])
	offset += n
	n ,size = get_uleb128(content[offset:5+offset])
	offset += n
	if is_root:
		str1 += lex_object.gettypenamebyid(type_idx)
	for i in xrange(0,size):
		n ,name_idx = get_uleb128(content[offset:5+offset])
		if i == 0 and is_root:
			str1 += lex_object.getstringbyid(name_idx)
		offset += n
		size,text = parse_encoded_value1(lex_object,content[offset:],is_root)
		offset += size
		str1 += text
	return offset, str1
def parse_encoded_annotation(lex_object,content,is_root=False):
	offset = 0
	n ,type_idx = get_uleb128(content[offset:5+offset])
	offset += n
	n ,size = get_uleb128(content[offset:5+offset])
	offset += n
	if is_root:
		print lex_object.gettypenamebyid(type_idx),
	for i in xrange(0,size):
		n ,name_idx = get_uleb128(content[offset:5+offset])
		if i == 0 and is_root:
			print lex_object.getstringbyid(name_idx),
		offset += n
		offset += parse_encoded_value(lex_object,content[offset:],is_root)
	return offset

def parse_annotation_set_item(lex_object,offset,is_root=False):

	size, = struct.unpack_from("I",lex_object.m_content,offset)
	offset += struct.calcsize("I")
	for i in xrange(0,size):
		off,=struct.unpack_from("I",lex_object.m_content,offset)
		visibility, = struct.unpack_from("B",lex_object.m_content,off)
		if visibility == 0:
			print "VISIBILITY_BUILD",
		elif visibility == 1: 
			print "VISIBILITY_RUNTIME",
		elif visibility == 2: 
			print "VISIBILITY_SYSTEM",
		else:
			print "visibility is unknow %02x"%visibility
		off += struct.calcsize("B")
		parse_encoded_annotation(lex_object,lex_object.m_content[off:],True)
		offset += struct.calcsize("I")
		print ""

def parse_annotation_set_ref_list(lex_object,offset,is_root=False):
	size, = struct.unpack_from("I",lex_object.m_content,offset)
	offset += struct.calcsize("I")
	for i in xrange(0,size):
		off,=struct.unpack_from("I",lex_object.m_content,offset)
		parse_annotation_set_item(lex_object,off,True)
		offset += struct.calcsize("I")

def get_encoded_field(content):
	n , val1 = get_uleb128(content)
	n1 , val2 = get_uleb128(content[n:])
	return n + n1, val1, val2

def get_encoded_method(content):
	n , val1 = get_uleb128(content)
	n1 , val2 = get_uleb128(content[n:])
	n2 , val3 = get_uleb128(content[n+n1:])
	return n + n1 + n2, val1, val2, val3

class dex_parser:
	
	def __init__(self,filename):
		global DEX_MAGIC
		global DEX_OPT_MAGIC
		self.m_javaobject_id = 0
		self.m_filename = filename
		self.m_fd = open(filename,"rb")
		self.m_content = self.m_fd.read()
		self.m_fd.close()
		self.m_dex_optheader = None
		self.m_class_name_id = {}
		self.string_table = []
		if self.m_content[0:4] == DEX_OPT_MAGIC:
			self.init_optheader(self.m_content)
			self.init_header(self.m_content,0x40)
		elif self.m_content[0:4] == DEX_MAGIC:
			self.init_header(self.m_content,0)

		bOffset = self.m_stringIdsOff
		if self.m_stringIdsSize > 0:
			for i in xrange(0,self.m_stringIdsSize):
				offset, = struct.unpack_from("I",self.m_content,bOffset + i * 4)
				if i == 0:
					start = offset
				else:			
					skip, length = get_uleb128(self.m_content[start:start+5])
					self.string_table.append(self.m_content[start+skip:offset-1])
					start = offset
			for i in xrange(start,len(self.m_content)):
				if self.m_content[i]==chr(0):
					self.string_table.append(self.m_content[start+1:i])
					break			
		

		'''2013/3/19
		for i in xrange(0,self.m_methodIdsSize):
			print self.getmethodname(i)
		for i in xrange(0,self.m_fieldIdsSize):
			print self.getfieldname(i)
		for i in xrange(0,self.m_typeIdsSize):
			print self.gettypename(i)
		for i in xrange(0,self.m_protoIdsSize):
			print self.getprotoname(i)
		'''
		for i in xrange(0,self.m_classDefSize):
			str1 = self.getclassname(i)
			self.m_class_name_id[str1] = i
		for i in xrange(0,self.m_classDefSize):
			dex_class(self,i).printf(self)
			pass
			#self.getclass(i)
	def create_all_header(self):
		for i in xrange(0,self.m_classDefSize):
			str1 = self.getclassname(i)
			self.create_cpp_header(str1)	
	def create_cpp_header(self,classname="Landroid/app/Activity;"):
		if self.m_class_name_id.has_key(classname):
			classid= self.m_class_name_id[classname]
			field_list = dex_class(self,classid).create_header_file_for_cplusplus(self)
		pass
	def getstringbyid(self,stridx):
		if stridx >= self.m_stringIdsSize:
			return ""
		return self.string_table[stridx]
	
	def getmethodname(self,methodid):
		if methodid >= self.m_methodIdsSize:
			return ""
		offset = self.m_methodIdsOffset + methodid * struct.calcsize("HHI")
		class_idx,proto_idx,name_idx, = struct.unpack_from("HHI",self.m_content,offset)
		return self.string_table[name_idx]
	def getmethodfullname(self,methodid,hidden_classname=False):
		if methodid >= self.m_methodIdsSize:
			return ""
		offset = self.m_methodIdsOffset + methodid * struct.calcsize("HHI")
		class_idx,proto_idx,name_idx, = struct.unpack_from("HHI",self.m_content,offset)
		classname = self.gettypename(class_idx)
		classname = shorty_decode(classname)
		funcname = self.getstringbyid(name_idx)
		if not hidden_classname:
			classname = ""
		return self.getprotofullname(proto_idx,classname,funcname)
	def getmethodfullname1(self,methodid,parameter_list=[],hidden_classname=False):
		if methodid >= self.m_methodIdsSize:
			return ""
		offset = self.m_methodIdsOffset + methodid * struct.calcsize("HHI")
		class_idx,proto_idx,name_idx, = struct.unpack_from("HHI",self.m_content,offset)
		classname = self.gettypename(class_idx)
		classname = shorty_decode(classname)
		funcname = self.getstringbyid(name_idx)
		if not hidden_classname:
			classname = ""
		return self.getprotofullname1(proto_idx,classname,parameter_list,funcname)
	def getfieldname(self,fieldid):
		if fieldid >= self.m_fieldIdsSize:
			return ""
		offset = self.m_fieldIdsOffset + fieldid * struct.calcsize("HHI")
		class_idx,type_idx,name_idx, = struct.unpack_from("HHI",self.m_content,offset)
		return self.string_table[name_idx]
	def getfieldfullname1(self,fieldid):
		if fieldid >= self.m_fieldIdsSize:
			return ""
		offset = self.m_fieldIdsOffset + fieldid * struct.calcsize("HHI")
		class_idx,type_idx,name_idx, = struct.unpack_from("HHI",self.m_content,offset)		
		name = self.gettypename(type_idx)
		name = shorty_decode(name)
		index = name.rfind(".")
		fname = self.getstringbyid(name_idx)
		return "%s %s"%(name[index+1:],fname)	
	def getfieldfullname2(self,fieldid):
		if fieldid >= self.m_fieldIdsSize:
			return ""
		offset = self.m_fieldIdsOffset + fieldid * struct.calcsize("HHI")
		class_idx,type_idx,name_idx, = struct.unpack_from("HHI",self.m_content,offset)		
		typename = self.gettypename(type_idx)
		typename = shorty_decode(typename)
		fieldname = self.getstringbyid(name_idx)
		return typename,fieldname		
	def getfieldfullname(self,fieldid):
		if fieldid >= self.m_fieldIdsSize:
			return ""
		offset = self.m_fieldIdsOffset + fieldid * struct.calcsize("HHI")
		class_idx,type_idx,name_idx, = struct.unpack_from("HHI",self.m_content,offset)		
		name = self.gettypename(type_idx)
		name = shorty_decode(name)
		fname = self.getstringbyid(name_idx)
		return "%s %s"%(name,fname)
	def getfieldtypename(self,fieldid):
		if fieldid >= self.m_fieldIdsSize:
			return ""
		offset = self.m_fieldIdsOffset + fieldid * struct.calcsize("HHI")
		class_idx,type_idx,name_idx, = struct.unpack_from("HHI",self.m_content,offset)		
		name = self.gettypename(type_idx)
		if name[-1] != ";":
			name = shorty_decode(name) 
		return name

	def gettypename(self,typeid):
		if typeid >= self.m_typeIdsSize:
			return ""
		offset = self.m_typeIdsOffset + typeid * struct.calcsize("I")
		descriptor_idx, = struct.unpack_from("I",self.m_content,offset)
		return self.string_table[descriptor_idx]
	
	def getprotoname(self,protoid):
		if protoid >= self.m_protoIdsSize:
			return ""
		offset = self.m_protoIdsOffset + protoid * struct.calcsize("3I")
		shorty_idx,return_type_idx,parameters_off, = struct.unpack_from("3I",self.m_content,offset)
		return self.string_table[shorty_idx]
	def getprotofullname(self,protoid,classname,func_name):
		if protoid >= self.m_protoIdsSize:
			return ""
		offset = self.m_protoIdsOffset + protoid * struct.calcsize("3I")
		shorty_idx,return_type_idx,parameters_off, = struct.unpack_from("3I",self.m_content,offset)
		retname = self.gettypename(return_type_idx)
		retname = shorty_decode(retname)
		retstr =  retname+" " 
		if len(classname)==0:
			retstr += "%s("%func_name
		else:
			retstr +=  "%s::%s("%(classname,func_name)
		if parameters_off != 0:
			offset = parameters_off
			size, = struct.unpack_from("I",self.m_content,offset)
			offset += struct.calcsize("I")
			n = 0
			for i in xrange(0,size):
				type_idx, = struct.unpack_from("H",self.m_content,offset)
				offset += struct.calcsize("H")
				arg = self.gettypename(type_idx)
				arg = shorty_decode(arg)
				if n != 0:
					retstr += ","
				retstr+=arg
				n += 1
		retstr += ")"
		return retstr
	def getprotofullname1(self,protoid,classname,parameter_list,func_name):
		index = classname.rfind(".")
		classname = classname[index+1:]
		if protoid >= self.m_protoIdsSize:
			return ""
		offset = self.m_protoIdsOffset + protoid * struct.calcsize("3I")
		shorty_idx,return_type_idx,parameters_off, = struct.unpack_from("3I",self.m_content,offset)
		retname = self.gettypename(return_type_idx)
		retname = shorty_decode(retname)
		index = retname.rfind(".")
		retname = retname[index+1:]
		retstr =  retname+" " 
		#if len(classname)==0:
		retstr += "%s("%func_name
		#else:
		#	retstr +=  "%s::%s("%(classname,func_name)
		param_count = len(parameter_list)
		if parameters_off != 0:
			offset = parameters_off
			size, = struct.unpack_from("I",self.m_content,offset)
			offset += struct.calcsize("I")
			n = 0
			for i in xrange(0,size):
				type_idx, = struct.unpack_from("H",self.m_content,offset)
				offset += struct.calcsize("H")
				arg = self.gettypename(type_idx)
				arg = shorty_decode(arg)
				if n != 0:
					retstr += ","
				index = arg.rfind(".")
				arg = arg[index+1:]
				retstr+=arg
				if i < param_count:
					retstr += " "
					retstr += parameter_list[i]
				n += 1
		retstr += ")"
		return retstr	
	def getclassmethod_count(self,classid):
		if classid >= self.m_classDefSize:
			return ""
		offset = self.m_classDefOffset + classid * struct.calcsize("8I")
		class_idx,access_flags,superclass_idx,interfaces_off,source_file_idx,annotations_off,class_data_off,static_values_off,= struct.unpack_from("8I",self.m_content,offset)
		if class_data_off:
			offset = class_data_off
			n,static_fields_size = get_uleb128(self.m_content[offset:])
			offset += n
			n,instance_fields_size = get_uleb128(self.m_content[offset:])
			offset += n
			n,direct_methods_size = get_uleb128(self.m_content[offset:])
			offset += n
			n,virtual_methods_size = get_uleb128(self.m_content[offset:])
			offset += n
			return static_fields_size + instance_fields_size
		return 0
	def getclassmethod(classid,method_idx):
		count = 0
		if classid >= self.m_classDefSize:
			return ""
		offset = self.m_classDefOffset + classid * struct.calcsize("8I")
		class_idx,access_flags,superclass_idx,interfaces_off,source_file_idx,annotations_off,class_data_off,static_values_off,= struct.unpack_from("8I",self.m_content,offset)
		if class_data_off:
			offset = class_data_off
			n,static_fields_size = get_uleb128(self.m_content[offset:])
			offset += n
			n,instance_fields_size = get_uleb128(self.m_content[offset:])
			offset += n
			n,direct_methods_size = get_uleb128(self.m_content[offset:])
			offset += n
			n,virtual_methods_size = get_uleb128(self.m_content[offset:])
			offset += n
			count = direct_methods_size + virtual_methods_size
		if method_idx >= count:
			return ""
		ncount = static_fields_size + instance_fields_size
		ncount *= 2
		for i in xrange(0,ncount):
			n,tmp = get_uleb128(self.m_content[offset:])
			offset += n
		ncount *= 3
		for i in xrange(0,ncount):
			n,tmp = get_uleb128(self.m_content[offset:])
			offset += n
		n,method_idx_diff= get_uleb128(self.m_content[offset:])
		offset += n
		n,access_flags = get_uleb128(self.m_content[offset:])
		offset += n
		n,code_off = get_uleb128(self.m_content[offset:])
		

	def getclassname(self,classid):
		if classid >= self.m_classDefSize:
			return ""
		offset = self.m_classDefOffset + classid * struct.calcsize("8I")
		class_idx,access_flags,superclass_idx,interfaces_off,source_file_idx,annotations_off,class_data_off,static_values_off,= struct.unpack_from("8I",self.m_content,offset)
		return self.gettypename(class_idx)
	
	def init_optheader(self,content):
		offset = 0
		format = "4s"
		self.m_magic, = struct.unpack_from(format,content,offset)
		format = "I"
		offset += struct.calcsize(format)
		self.m_version, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_dexOffset, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_dexLength, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_depsOffset, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_depsLength, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_optOffset, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_optLength, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_flags, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_checksum, = struct.unpack_from(format,content,offset)

	def init_header(self,content,offset):
		
		format = "4s"
		self.m_magic, = struct.unpack_from(format,content,offset)
		format = "I"
		offset += struct.calcsize(format)
		self.m_version, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_checksum, = struct.unpack_from(format,content,offset)
		format = "20s"
		offset += struct.calcsize(format)
		self.m_signature, = struct.unpack_from(format,content,offset)
		format = "I"
		offset += struct.calcsize(format)
		self.m_fileSize, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_headerSize, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_endianTag, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_linkSize, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_linkOff, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_mapOffset, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_stringIdsSize, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_stringIdsOff, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_typeIdsSize, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_typeIdsOffset, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_protoIdsSize, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_protoIdsOffset, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_fieldIdsSize, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_fieldIdsOffset, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_methodIdsSize, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_methodIdsOffset, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_classDefSize, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_classDefOffset, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_dataSize, = struct.unpack_from(format,content,offset)
		offset += struct.calcsize(format)
		self.m_dataOff, = struct.unpack_from(format,content,offset)
	def gettypenamebyid(self,typeid):
		if typeid >= self.m_typeIdsSize:
			return ""
		offset = self.m_typeIdsOffset + typeid * struct.calcsize("I")
		descriptor_idx, = struct.unpack_from("I",self.m_content,offset)
		return self.string_table[descriptor_idx]
	'''
	def getclassnamebyid(self,classidx):
		if classidx < len(self.classDef_list):
			return gettypenamebyid(self.classDef_list[classidx].class_idx)
		return ""
	def getfieldnamebyfieldid(self,fieldid):
		if fieldid < len(self.FieldId_list):
			return self.FieldId_list[fieldid].getfieldname(self)
		return ""
	def getfieldfullnamebyfieldid(self,fieldid):
		if fieldid < len(self.FieldId_list):
			return self.FieldId_list[fieldid].getfullname(self)
		return ""
	def getmethodnamebyid(self,methodid):
		if methodid < len(self.MethodId_list):
			return self.MethodId_list[methodid].getmethodname(self)
		return ""
	def getmethodfullnamebyid(self,methodid,show_class_name=False):
		if methodid < len(self.MethodId_list):
			return self.MethodId_list[methodid].getfullname(self,show_class_name)
		return ""
	'''
	def get_access_flags(self,flags):
		val = {1:"public",
			2:"private",
			4:"protected",
			8:"static",
			0x10:"final",
			0x20:"synchronized",
			0x40:"volatile",
			0x80:"bridge",
			0x100:"native",
			0x200:"interface",
			0x400:"abstract",
			0x800:"strict",
			0x1000:"synthetic",
			0x2000:"annotation",
			0x4000:"enum",
			0x8000:"unused",
			0x10000:"constructor",
			0x20000:"declared_synchronized"
		}
		value = ""
		i = 0
		for key in val:
			if key & flags:
				if i != 0:
					value += " "
				value += val[key]
				i+=1
		if i == 0:
			value += "public "
		
		return value
	def get_access_flags1(self,flags):
		val = {1:"public",
			2:"private",
			4:"protected"
		}
		value = ""
		i = 0
		for key in val:
			if key & flags:
				if i != 0:
					value += " "
				value += val[key]
				i+=1
		if i == 0:
			value += "public"
			flags = 1
		
		return value+":",flags		
	def getclass(self,classid):
		'''
		if classid >= self.m_classDefSize:
			return ""
		offset = self.m_classDefOffset + classid * struct.calcsize("8I")
		#typeid,superclass,modifiers,numSFields,numIFields,numVMethod,numDMethod,numSMethod,ClassDataOff,interfaceOff,annotationsOff,staticValuesOff,sourceFileIdx,= struct.unpack_from("2I6H5I",self.m_content,offset)
		class_idx,access_flags,superclass_idx,interfaces_off,source_file_idx,annotations_off,class_data_off,static_values_off,= struct.unpack_from("8I",self.m_content,offset)
		if class_data_off:
			offset = class_data_off
			n,static_fields_size = get_uleb128(self.m_content[offset:])
			offset += n
			n,instance_fields_size = get_uleb128(self.m_content[offset:])
			offset += n
			n,direct_methods_size = get_uleb128(self.m_content[offset:])
			offset += n
			n,virtual_methods_size = get_uleb128(self.m_content[offset:])
			offset += n
			count = direct_methods_size + virtual_methods_size
		classname = self.gettypename(class_idx)
		supername = self.gettypename(superclass_idx)
		interfacestr = ""
		
		if interfaces_off:
			count, = struct.unpack_from("I",self.m_content,interfaces_off)
			print "interfaces_off=%d %s%s %d   count=%d [%x]"%(interfaces_off,classname,supername,len(self.m_content),count,count)
			for i in xrange(0,count):
				idx = struct.unpack_from("H",self.m_content,interfaces_off+struct.calcsize("I")+i*struct.calcsize("H"))
				iname = self.gettypename(idx)
				if i != 0:
					interfacestr += ", "
				interfacestr += iname
		if len(supername)>0:
			supername = " extends %s"%supername
		if len(interfacestr)>0:
			interfacestr = " implements %s"%interfacestr
		offset = class_data_off
		print "class %s%s%s\n{\n"%(classname,supername,interfacestr)
		prefix="\t\t"
		staticoffset = static_values_off
		staticindex = 0
		for i in xrange(0,numSFields):
			fieldIdx, modifiers, = struct.unpack_from("2H",self.m_content,offset)
			print prefix + self.getfieldfullname(fieldIdx),
			offset += struct.calcsize("2H")
			userbyte,value = get_encoded_array_by_index(self.m_content[staticoffset:],i)
			print value
		for i in xrange(0,numIFields):			
			fieldIdx, modifiers, = struct.unpack_from("2H",self.m_content,offset)
			print prefix + self.getfieldfullname(fieldIdx)
			offset += struct.calcsize("2H")

		for i in xrange(0,numVMethod):			
			methodIdx, modifiers, codeOff, = struct.unpack_from("2HI",self.m_content,offset)
			print prefix + self.getmethodfullname(methodIdx,True)
			offset += struct.calcsize("2HI")

		for i in xrange(0,numDMethod):			
			methodIdx, modifiers, codeOff, = struct.unpack_from("2HI",self.m_content,offset)
			print prefix + self.getmethodfullname(methodIdx,True)
			offset += struct.calcsize("2HI")

		for i in xrange(0,numSMethod):			
			methodIdx, modifiers, codeOff, = struct.unpack_from("2HI",self.m_content,offset)
			print prefix + self.getmethodfullname(methodIdx,True)
			offset += struct.calcsize("2HI")
		print "}\n"
		'''
def main():
	if len(sys.argv) < 2:
		print "Usages: %s dex_file"%sys.argv[0]
		quit()
	
	filename = "classes.dex"
	dex = dex_parser(filename)
	
	
def draw_graphics(class_list):
	for class_name in class_list:
		pass
if __name__ == "__main__":
	main()
