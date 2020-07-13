import struct

def get_uleb128p1(content):
	n,value = get_uleb128(content)
	value -= 1
	return n,value  

def get_uleb128(content):
	value = 0
	for i in xrange(0,5):
		tmp = ord(content[i]) & 0x7f
		value = tmp << (i * 7) | value
		if (ord(content[i]) & 0x80) != 0x80:
			break
	if i == 4 and (tmp & 0xf0) != 0:
		print "parse a error uleb128 number"
		return -1
	return i+1, value

def get_leb128(content):
	value = 0
	
	mask=[0xffffff80,0xffffc000,0xffe00000,0xf0000000,0]
	bitmask=[0x40,0x40,0x40,0x40,0x8]
	value = 0
	for i in xrange(0,5):
		tmp = ord(content[i]) & 0x7f
		value = tmp << (i * 7) | value
		if (ord(content[i]) & 0x80) != 0x80:
			if bitmask[i] & tmp:
				value |= mask[i]
			break
	if i == 4 and (tmp & 0xf0) != 0:
		print "parse a error uleb128 number"
		return -1
	buffer = struct.pack("I",value)
	value, =struct.unpack("i",buffer)
	return i+1, value