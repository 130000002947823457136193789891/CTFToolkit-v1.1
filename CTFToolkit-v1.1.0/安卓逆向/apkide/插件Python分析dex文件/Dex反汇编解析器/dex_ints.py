import struct
FMT10T = 0
FMT10X = 1
FMT11N = 2
FMT11X = 3
FMT12X = 4
FMT20T = 5
FMT21C = 6
FMT21H = 7
FMT21S = 8
FMT21T = 9
FMT22B = 10
FMT22C = 11
FMT22S = 12
FMT22T = 13
FMT22X = 14
FMT23X = 15
FMT30T = 16
FMT31C = 17
FMT31I = 18
FMT31T = 19
FMT32X = 20
FMT35C = 21
FMT3RC = 22
FMT51L = 23

list1 = ['fmt10t', 'fmt10x', 'fmt11n', 'fmt11x', 'fmt12x', 'fmt20t', 'fmt21c', 'fmt21h',
 'fmt21s', 'fmt21t', 'fmt22b', 'fmt22c', 'fmt22s', 'fmt22t', 'fmt22x', 'fmt23x',
 'fmt30t', 'fmt31c', 'fmt31i', 'fmt31t', 'fmt32x', 'fmt35c', 'fmt3rc', 'fmt51l']

def parse_FMT10X(buffer,dex_object,pc_point,offset):
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1])
def parse_FMT10T(buffer,dex_object,pc_point,offset):
	val, = struct.unpack_from("b",buffer,1)
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"%04x"%(val+offset))
def parse_FMT11N(buffer,dex_object,pc_point,offset):
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%(ord(buffer[1])&0xf),"%d"%((ord(buffer[1])>>4)&0xf))
def parse_FMT11X(buffer,dex_object,pc_point,offset):
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]))
def parse_FMT12X(buffer,dex_object,pc_point,offset):
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%(ord(buffer[1])&0x0f),"v%d"%((ord(buffer[1])>>4)&0xf))
def parse_FMT20T(buffer,dex_object,pc_point,offset):
	v ,= struct.unpack_from("h",buffer,2)
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"%04x"%(v+offset))
def parse_FMT21C(buffer,dex_object,pc_point,offset):
	val = ord(buffer[0])
	
	v, = struct.unpack_from("H",buffer,2)
	arg1 = "@%d"%v
	if val == 0x1a:
		arg1 = "\"%s\""%dex_object.getstringbyid(v)
	elif val in [0x1c,0x1f,0x22]:
		arg1 = "type@%s"%dex_object.gettypename(v)
	else:
		arg1 = "field@%s  //%s"%(dex_object.getfieldname(v),dex_object.getfieldfullname(v))
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),arg1)
def parse_FMT21H(buffer,dex_object,pc_point,offset):
	v, = struct.unpack_from("H",buffer,2)
	if ord(buffer[1]) == 0x19:
		arg1 = "@%d000000000000"%v
	else:
		arg1 = "@%d0000"%v
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),arg1)
def parse_FMT21S(buffer,dex_object,pc_point,offset):
	v, = struct.unpack_from("H",buffer,2)
	arg1 = "%d"%v
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),arg1)
def parse_FMT21T(buffer,dex_object,pc_point,offset):
	v, = struct.unpack_from("h",buffer,2)
	arg1 = "%04x"%(v+offset)
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),arg1)
def parse_FMT22B(buffer,dex_object,pc_point,offset):
	cc,bb,=struct.unpack_from("Bb",buffer,2)
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),"v%d"%bb,"%d"%cc)
def parse_FMT22C(buffer,dex_object,pc_point,offset):
	cccc,=struct.unpack_from("H",buffer,2)
	if ord(buffer[0]) == 0x20 or ord(buffer[0]) == 0x23:
		prefix="type@%s"%(dex_object.gettypename(cccc))
	else:
		prefix="field@%s  //%s"%(dex_object.getfieldname(cccc),dex_object.getfieldfullname(cccc))

	
	bb = ord(buffer[1])>>4
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%(ord(buffer[1])&0xf),"v%d"%((ord(buffer[1])>>4)&0xf),"%s"%prefix)
def parse_FMT22S(buffer,dex_object,pc_point,offset):
	bb = ord(buffer[1])>>4
	cccc,=struct.unpack_from("h",buffer,2)
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%(ord(buffer[1])&0xf),"v%d"%((ord(buffer[1])>>4)&0xf),"%d"%cccc)
def parse_FMT22T(buffer,dex_object,pc_point,offset):
	bb = ord(buffer[1])>>4
	cccc,=struct.unpack_from("h",buffer,2)

	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%(ord(buffer[1])&0xf),"v%d"%((ord(buffer[1])>>4)&0xf),"%04x"%(cccc+offset))
def parse_FMT22X(buffer,dex_object,pc_point,offset):
	v, = struct.unpack_from("h",buffer,2)
	arg1 = "v%d"%v
	return ( dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),arg1)
def parse_FMT23X(buffer,dex_object,pc_point,offset):
	cc,bb,=struct.unpack_from("Bb",buffer,2)
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),"v%d"%bb,"v%d"%cc)
def parse_FMT30T(buffer,dex_object,pc_point,offset):
	aaaaaaaa,=struct.unpack_from("i",buffer,2)
	return dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"+%x"%(aaaaaaaa+offset)
def parse_FMT31C(buffer,dex_object,pc_point,offset):
	bbbbbbbb,=struct.unpack_from("I",buffer,2)
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),"+%d"%bbbbbbbb)
def parse_FMT31I(buffer,dex_object,pc_point,offset):
	bbbbbbbb,=struct.unpack_from("I",buffer,2)
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),"%d"%bbbbbbbb)
def parse_FMT31T(buffer,dex_object,pc_point,offset):
	bbbbbbbb,=struct.unpack_from("i",buffer,2)
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),"string@%d"%bbbbbbbb)

def parse_FMT32X(buffer,dex_object,pc_point,offset):
	aaaa,bbbb,=struct.unpack_from("hh",buffer,2)
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%aaaa,"v%d"%bbbb)
def parse_FMT35C(buffer,dex_object,pc_point,offset):
	

	A = ord(buffer[1])>>4
	G = ord(buffer[1])&0xf
	D = ord(buffer[4])>>4
	C = ord(buffer[4])&0xf
	F = ord(buffer[5])>>4
	E = ord(buffer[5])&0xf
	bbbb,=struct.unpack_from("H",buffer,2)
	if ord(buffer[0]) == 0x24:
		prefix="type@%s"%(dex_object.getstringbyid(bbbb))
	else:
		prefix="meth@%s  //%s"%(dex_object.getmethodname(bbbb),dex_object.getmethodfullname(bbbb,True))
		pass
	if A == 5:
		return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%C,"v%d"%D,"v%d"%E,"v%d"%F,"v%d"%G,"%s"%(prefix))
	elif A == 4:
		return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%C,"v%d"%D,"v%d"%E,"v%d"%F,"%s"%(prefix))
	elif A == 3:
		return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%C,"v%d"%D,"v%d"%E,"%s"%(prefix))
	elif A == 2:
		return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%C,"v%d"%D,"%s"%(prefix))
	elif A == 1:
		return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%C,"%s"%(prefix))
	elif A == 0:
		return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"%s"%(prefix))
	else:
		return (dex_decode[ord(buffer[0])][4],"error .......")
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%C,"v%d"%D,"v%d"%E,"v%d"%F,"v%d"%G,"%s"%(prefix))
def parse_FMT3RC(buffer,dex_object,pc_point,offset):
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1])
def parse_FMT51L(buffer,dex_object,pc_point,offset):
	if len(buffer) <10:
		return (1,"")
	bb=struct.unpack_from("q",buffer,2)
	return (dex_decode[ord(buffer[0])][4],dex_decode[ord(buffer[0])][1],"v%d"%ord(buffer[1]),"%d"%bb)

func_point=[parse_FMT10T, parse_FMT10X, parse_FMT11N, parse_FMT11X, parse_FMT12X, parse_FMT20T, parse_FMT21C, parse_FMT21H, parse_FMT21S, parse_FMT21T, parse_FMT22B, parse_FMT22C, parse_FMT22S, parse_FMT22T, parse_FMT22X, parse_FMT23X, parse_FMT30T, parse_FMT31C, parse_FMT31I, parse_FMT31T, parse_FMT32X, parse_FMT35C, parse_FMT3RC, parse_FMT51L]

def parse_instruction(buffer,offset,dex_object):
	
	n = len(buffer)
	start = 0
	
	while start < n:
		if n == 1736:
			print "start = %d"%start
		op = ord(buffer[start])
		if op == 0:
			type = ord(buffer[start+1])
			if type == 1:
				size,=struct.unpack_from("H",buffer,2+start)
				start += (size * 2 + 4) * 2
				continue				
			elif type == 2:
				size,=struct.unpack_from("H",buffer,2+start)
				start += (size * 4 + 2) * 2
				continue
			elif type == 3:
				width, = struct.unpack_from("H",buffer,2+start)
				size, = struct.unpack_from("I",buffer,4+start)	
				#width,size,=struct.unpack_from("HI",buffer,2+start)
				start+=(8 + ((size*width+1)/2)*2)
				continue

		val = func_point[dex_decode[op][3]](buffer[start:],dex_object,offset+start,start/2)
		str=""
		m = 0
		for x in buffer[start:start+2*val[0]]:
			str+="%02x"%ord(x)
			m+=1
			if m %2 ==0:
				str+=" "
		
		print "%08x: %-36s |%04x:"%(offset+start,str,start/2),
		m = 0
		for v in val[1:]:
			if m >1:
				print ",",
			print v,
			m+=1
		print ""
		start += 2*val[0]

dex_decode={
	0:(0x00,'nop','fmt10x',FMT10X,1),
	1:(0x01,'move','fmt12x',FMT12X,1),
	2:(0x02,'move/from16','fmt22x',FMT22X,2),
	3:(0x03,'move/16','fmt32x',FMT32X,3),
	4:(0x04,'move-wide','fmt12x',FMT12X,1),
	5:(0x05,'move-wide/from16','fmt22x',FMT22X,2),
	6:(0x06,'move-wide/16','fmt32x',FMT32X,3),
	7:(0x07,'move-object','fmt12x',FMT12X,1),
	8:(0x08,'move-object/from16','fmt22x',FMT22X,2),
	9:(0x09,'move-object/16','fmt32x',FMT32X,3),
	10:(0x0a,'move-result','fmt11x',FMT11X,1),
	11:(0x0b,'move-result-wide','fmt11x',FMT11X,1),
	12:(0x0c,'move-result-object','fmt11x',FMT11X,1),
	13:(0x0d,'move-exception','fmt11x',FMT11X,1),
	14:(0x0e,'return-void','fmt10x',FMT10X,1),
	15:(0x0f,'return','fmt11x',FMT11X,1),
	16:(0x10,'return-wide','fmt11x',FMT11X,1),
	17:(0x11,'return-object','fmt11x',FMT11X,1),
	18:(0x12,'const/4','fmt11n',FMT11N,1),
	19:(0x13,'const/16','fmt21s',FMT21S,2),
	20:(0x14,'const','fmt31i',FMT31I,3),
	21:(0x15,'const/high16','fmt21h',FMT21H,2),
	22:(0x16,'const-wide/16','fmt21s',FMT21S,2),
	23:(0x17,'const-wide/32','fmt31i',FMT31I,3),
	24:(0x18,'const-wide','fmt51l',FMT51L,5),
	25:(0x19,'const-wide/high16','fmt21h',FMT21H,2),
	26:(0x1a,'const-string','fmt21c',FMT21C,2),
	27:(0x1b,'const-string/jumbo','fmt31c',FMT31C,3),
	28:(0x1c,'const-class','fmt21c',FMT21C,2),
	29:(0x1d,'monitor-enter','fmt11x',FMT11X,1),
	30:(0x1e,'monitor-exit','fmt11x',FMT11X,1),
	31:(0x1f,'check-cast','fmt21c',FMT21C,2),
	32:(0x20,'instance-of','fmt22c',FMT22C,2),
	33:(0x21,'array-length','fmt12x',FMT12X,1),
	34:(0x22,'new-instance','fmt21c',FMT21C,2),
	35:(0x23,'new-array','fmt22c',FMT22C,2),
	36:(0x24,'filled-new-array','fmt35c',FMT35C,3),
	37:(0x25,'filled-new-array/range','fmt3rc',FMT3RC,3),
	38:(0x26,'fill-array-data','fmt31t',FMT31T,3),
	39:(0x27,'throw','fmt11x',FMT11X,1),
	40:(0x28,'goto','fmt10t',FMT10T,1),
	41:(0x29,'goto/16','fmt20t',FMT20T,2),
	42:(0x2a,'goto/32','fmt30t',FMT30T,3),
	43:(0x2b,'packed-switch','fmt31t',FMT31T,3),
	44:(0x2c,'sparse-switch','fmt31t',FMT31T,3),
	45:(0x2d,'cmpl-float','fmt23x',FMT23X,2),
	46:(0x2e,'cmpg-float','fmt23x',FMT23X,2),
	47:(0x2f,'cmpl-double','fmt23x',FMT23X,2),
	48:(0x30,'cmpg-double','fmt23x',FMT23X,2),
	49:(0x31,'cmp-long','fmt23x',FMT23X,2),
	50:(0x32,'if-eq','fmt22t',FMT22T,2),
	51:(0x33,'if-ne','fmt22t',FMT22T,2),
	52:(0x34,'if-lt','fmt22t',FMT22T,2),
	53:(0x35,'if-ge','fmt22t',FMT22T,2),
	54:(0x36,'if-gt','fmt22t',FMT22T,2),
	55:(0x37,'if-le','fmt22t',FMT22T,2),
	56:(0x38,'if-eqz','fmt21t',FMT21T,2),
	57:(0x39,'if-nez','fmt21t',FMT21T,2),
	58:(0x3a,'if-ltz','fmt21t',FMT21T,2),
	59:(0x3b,'if-gez','fmt21t',FMT21T,2),
	60:(0x3c,'if-gtz','fmt21t',FMT21T,2),
	61:(0x3d,'if-lez','fmt21t',FMT21T,2),
	62:(0x3e,'unused','fmt10x',FMT10X,1),
	63:(0x3f,'unused','fmt10x',FMT10X,1),
	64:(0x40,'unused','fmt10x',FMT10X,1),
	65:(0x41,'unused','fmt10x',FMT10X,1),
	66:(0x42,'unused','fmt10x',FMT10X,1),
	67:(0x43,'unused','fmt10x',FMT10X,1),
	68:(0x44,'aget','fmt23x',FMT23X,2),
	69:(0x45,'aget-wide','fmt23x',FMT23X,2),
	70:(0x46,'aget-object','fmt23x',FMT23X,2),
	71:(0x47,'aget-boolean','fmt23x',FMT23X,2),
	72:(0x48,'aget-byte','fmt23x',FMT23X,2),
	73:(0x49,'aget-char','fmt23x',FMT23X,2),
	74:(0x4a,'aget-short','fmt23x',FMT23X,2),
	75:(0x4b,'aput','fmt23x',FMT23X,2),
	76:(0x4c,'aput-wide','fmt23x',FMT23X,2),
	77:(0x4d,'aput-object','fmt23x',FMT23X,2),
	78:(0x4e,'aput-boolean','fmt23x',FMT23X,2),
	79:(0x4f,'aput-byte','fmt23x',FMT23X,2),
	80:(0x50,'aput-shar','fmt23x',FMT23X,2),
	81:(0x51,'aput-short','fmt23x',FMT23X,2),
	82:(0x52,'iget','fmt22c',FMT22C,2),
	83:(0x53,'iget-wide','fmt22c',FMT22C,2),
	84:(0x54,'iget-object','fmt22c',FMT22C,2),
	85:(0x55,'iget-boolean','fmt22c',FMT22C,2),
	86:(0x56,'iget-byte','fmt22c',FMT22C,2),
	87:(0x57,'iget-char','fmt22c',FMT22C,2),
	88:(0x58,'iget-short','fmt22c',FMT22C,2),
	89:(0x59,'iput','fmt22c',FMT22C,2),
	90:(0x5a,'iput-wide','fmt22c',FMT22C,2),
	91:(0x5b,'iput-object','fmt22c',FMT22C,2),
	92:(0x5c,'iput-boolean','fmt22c',FMT22C,2),
	93:(0x5d,'iput-byte','fmt22c',FMT22C,2),
	94:(0x5e,'iput-char','fmt22c',FMT22C,2),
	95:(0x5f,'iput-short','fmt22c',FMT22C,2),
	96:(0x60,'sget','fmt21c',FMT21C,2),
	97:(0x61,'sget-wide','fmt21c',FMT21C,2),
	98:(0x62,'sget-object','fmt21c',FMT21C,2),
	99:(0x63,'sget-boolean','fmt21c',FMT21C,2),
	100:(0x64,'sget-byte','fmt21c',FMT21C,2),
	101:(0x65,'sget-char','fmt21c',FMT21C,2),
	102:(0x66,'sget-short','fmt21c',FMT21C,2),
	103:(0x67,'sput','fmt21c',FMT21C,2),
	104:(0x68,'sput-wide','fmt21c',FMT21C,2),
	105:(0x69,'sput-object','fmt21c',FMT21C,2),
	106:(0x6a,'sput-boolean','fmt21c',FMT21C,2),
	107:(0x6b,'sput-byte','fmt21c',FMT21C,2),
	108:(0x6c,'sput-char','fmt21c',FMT21C,2),
	109:(0x6d,'sput-short','fmt21c',FMT21C,2),
	110:(0x6e,'invoke-virtual','fmt35c',FMT35C,3),
	111:(0x6f,'invoke-super','fmt35c',FMT35C,3),
	112:(0x70,'invoke-direct','fmt35c',FMT35C,3),
	113:(0x71,'invoke-static','fmt35c',FMT35C,3),
	114:(0x72,'invoke-insterface','fmt35c',FMT35C,3),
	115:(0x73,'unused','fmt10x',FMT10X,1),
	116:(0x74,'invoke-virtual/range','fmt3rc',FMT3RC,3),
	117:(0x75,'invoke-super/range','fmt3rc',FMT3RC,3),
	118:(0x76,'invoke-direct/range','fmt3rc',FMT3RC,3),
	119:(0x77,'invoke-static/range','fmt3rc',FMT3RC,3),
	120:(0x78,'invoke-interface/range','fmt3rc',FMT3RC,3),
	121:(0x79,'unused','fmt10x',FMT10X,1),
	122:(0x7a,'unused','fmt10x',FMT10X,1),
	123:(0x7b,'neg-int','fmt12x',FMT12X,1),
	124:(0x7c,'not-int','fmt12x',FMT12X,1),
	125:(0x7d,'neg-long','fmt12x',FMT12X,1),
	126:(0x7e,'not-long','fmt12x',FMT12X,1),
	127:(0x7f,'neg-float','fmt12x',FMT12X,1),
	128:(0x80,'neg-double','fmt12x',FMT12X,1),
	129:(0x81,'int-to-long','fmt12x',FMT12X,1),
	130:(0x82,'int-to-float','fmt12x',FMT12X,1),
	131:(0x83,'int-to-double','fmt12x',FMT12X,1),
	132:(0x84,'long-to-int','fmt12x',FMT12X,1),
	133:(0x85,'long-to-float','fmt12x',FMT12X,1),
	134:(0x86,'long-to-double','fmt12x',FMT12X,1),
	135:(0x87,'float-to-int','fmt12x',FMT12X,1),
	136:(0x88,'float-to-long','fmt12x',FMT12X,1),
	137:(0x89,'float-to-double','fmt12x',FMT12X,1),
	138:(0x8a,'double-to-int','fmt12x',FMT12X,1),
	139:(0x8b,'double-to-long','fmt12x',FMT12X,1),
	140:(0x8c,'double-to-float','fmt12x',FMT12X,1),
	141:(0x8d,'int-to-byte','fmt12x',FMT12X,1),
	142:(0x8e,'int-to-char','fmt12x',FMT12X,1),
	143:(0x8f,'int-to-short','fmt12x',FMT12X,1),
	144:(0x90,'add-int','fmt23x',FMT23X,2),
	145:(0x91,'sub-int','fmt23x',FMT23X,2),
	146:(0x92,'mul-int','fmt23x',FMT23X,2),
	147:(0x93,'div-int','fmt23x',FMT23X,2),
	148:(0x94,'rem-int','fmt23x',FMT23X,2),
	149:(0x95,'and-int','fmt23x',FMT23X,2),
	150:(0x96,'or-int','fmt23x',FMT23X,2),
	151:(0x97,'xor-int','fmt23x',FMT23X,2),
	152:(0x98,'shl-int','fmt23x',FMT23X,2),
	153:(0x99,'shr-int','fmt23x',FMT23X,2),
	154:(0x9a,'ushr-int','fmt23x',FMT23X,2),
	155:(0x9b,'add-long','fmt23x',FMT23X,2),
	156:(0x9c,'sub-long','fmt23x',FMT23X,2),
	157:(0x9d,'mul-long','fmt23x',FMT23X,2),
	158:(0x9e,'div-long','fmt23x',FMT23X,2),
	159:(0x9f,'rem-long','fmt23x',FMT23X,2),
	160:(0xa0,'and-long','fmt23x',FMT23X,2),
	161:(0xa1,'or-long','fmt23x',FMT23X,2),
	162:(0xa2,'xor-long','fmt23x',FMT23X,2),
	163:(0xa3,'shl-long','fmt23x',FMT23X,2),
	164:(0xa4,'shr-long','fmt23x',FMT23X,2),
	165:(0xa5,'ushr-long','fmt23x',FMT23X,2),
	166:(0xa6,'add-float','fmt23x',FMT23X,2),
	167:(0xa7,'sub-float','fmt23x',FMT23X,2),
	168:(0xa8,'mul-float','fmt23x',FMT23X,2),
	169:(0xa9,'div-float','fmt23x',FMT23X,2),
	170:(0xaa,'rem-float','fmt23x',FMT23X,2),
	171:(0xab,'add-double','fmt23x',FMT23X,2),
	172:(0xac,'sub-double','fmt23x',FMT23X,2),
	173:(0xad,'mul-double','fmt23x',FMT23X,2),
	174:(0xae,'div-double','fmt23x',FMT23X,2),
	175:(0xaf,'rem-double','fmt23x',FMT23X,2),
	176:(0xb0,'add-int/2addr','fmt12x',FMT12X,1),
	177:(0xb1,'sub-int/2addr','fmt12x',FMT12X,1),
	178:(0xb2,'mul-int/2addr','fmt12x',FMT12X,1),
	179:(0xb3,'div-int/2addr','fmt12x',FMT12X,1),
	180:(0xb4,'rem-int/2addr','fmt12x',FMT12X,1),
	181:(0xb5,'and-int/2addr','fmt12x',FMT12X,1),
	182:(0xb6,'or-int/2addr','fmt12x',FMT12X,1),
	183:(0xb7,'xor-int/2addr','fmt12x',FMT12X,1),
	184:(0xb8,'shl-int/2addr','fmt12x',FMT12X,1),
	185:(0xb9,'shr-int/2addr','fmt12x',FMT12X,1),
	186:(0xba,'ushr-int/2addr','fmt12x',FMT12X,1),
	187:(0xbb,'add-long/2addr','fmt12x',FMT12X,1),
	188:(0xbc,'sub-long/2addr','fmt12x',FMT12X,1),
	189:(0xbd,'mul-long/2addr','fmt12x',FMT12X,1),
	190:(0xbe,'div-long/2addr','fmt12x',FMT12X,1),
	191:(0xbf,'rem-long/2addr','fmt12x',FMT12X,1),
	192:(0xc0,'and-long/2addr','fmt12x',FMT12X,1),
	193:(0xc1,'or-long/2addr','fmt12x',FMT12X,1),
	194:(0xc2,'xor-long/2addr','fmt12x',FMT12X,1),
	195:(0xc3,'shl-long/2addr','fmt12x',FMT12X,1),
	196:(0xc4,'shr-long/2addr','fmt12x',FMT12X,1),
	197:(0xc5,'ushr-long/2addr','fmt12x',FMT12X,1),
	198:(0xc6,'add-float/2addr','fmt12x',FMT12X,1),
	199:(0xc7,'sub-float/2addr','fmt12x',FMT12X,1),
	200:(0xc8,'mul-float/2addr','fmt12x',FMT12X,1),
	201:(0xc9,'div-float/2addr','fmt12x',FMT12X,1),
	202:(0xca,'rem-float/2addr','fmt12x',FMT12X,1),
	203:(0xcb,'add-double/2addr','fmt12x',FMT12X,1),
	204:(0xcc,'sub-double/2addr','fmt12x',FMT12X,1),
	205:(0xcd,'mul-double/2addr','fmt12x',FMT12X,1),
	206:(0xce,'div-double/2addr','fmt12x',FMT12X,1),
	207:(0xcf,'rem-double/2addr','fmt12x',FMT12X,1),
	208:(0xd0,'add-int/lit16','fmt22s',FMT22S,2),
	209:(0xd1,'rsub-int','fmt22s',FMT22S,2),
	210:(0xd2,'mul-int/lit16','fmt22s',FMT22S,2),
	211:(0xd3,'div-int/lit16','fmt22s',FMT22S,2),
	212:(0xd4,'rem-int/lit16','fmt22s',FMT22S,2),
	213:(0xd5,'and-int/lit16','fmt22s',FMT22S,2),
	214:(0xd6,'or-int/lit16','fmt22s',FMT22S,2),
	215:(0xd7,'xor-int/lit16','fmt22s',FMT22S,2),
	216:(0xd8,'add-int/lit8','fmt22b',FMT22B,2),
	217:(0xd9,'rsub-int/lit8','fmt22b',FMT22B,2),
	218:(0xda,'mul-int/lit8','fmt22b',FMT22B,2),
	219:(0xdb,'div-int/lit8','fmt22b',FMT22B,2),
	220:(0xdc,'rem-int/lit8','fmt22b',FMT22B,2),
	221:(0xdd,'and-int/lit8','fmt22b',FMT22B,2),
	222:(0xde,'or-int/lit8','fmt22b',FMT22B,2),
	223:(0xdf,'xor-int/lit8','fmt22b',FMT22B,2),
	224:(0xe0,'shl-int/lit8','fmt22b',FMT22B,2),
	225:(0xe1,'shr-int/lit8','fmt22b',FMT22B,2),
	226:(0xe2,'ushr-int/lit8','fmt22b',FMT22B,2),
	227:(0xe3,'unused','fmt10x',FMT10X,1),
	228:(0xe4,'unused','fmt10x',FMT10X,1),
	229:(0xe5,'unused','fmt10x',FMT10X,1),
	230:(0xe6,'unused','fmt10x',FMT10X,1),
	231:(0xe7,'unused','fmt10x',FMT10X,1),
	232:(0xe8,'unused','fmt10x',FMT10X,1),
	233:(0xe9,'unused','fmt10x',FMT10X,1),
	234:(0xea,'unused','fmt10x',FMT10X,1),
	235:(0xeb,'unused','fmt10x',FMT10X,1),
	236:(0xec,'unused','fmt10x',FMT10X,1),
	237:(0xed,'unused','fmt10x',FMT10X,1),
	238:(0xee,'unused','fmt10x',FMT10X,1),
	239:(0xef,'unused','fmt10x',FMT10X,1),
	240:(0xf0,'unused','fmt10x',FMT10X,1),
	241:(0xf1,'unused','fmt10x',FMT10X,1),
	242:(0xf2,'unused','fmt10x',FMT10X,1),
	243:(0xf3,'unused','fmt10x',FMT10X,1),
	244:(0xf4,'unused','fmt10x',FMT10X,1),
	245:(0xf5,'unused','fmt10x',FMT10X,1),
	246:(0xf6,'unused','fmt10x',FMT10X,1),
	247:(0xf7,'unused','fmt10x',FMT10X,1),
	248:(0xf8,'unused','fmt10x',FMT10X,1),
	249:(0xf9,'unused','fmt10x',FMT10X,1),
	250:(0xfa,'unused','fmt10x',FMT10X,1),
	251:(0xfb,'unused','fmt10x',FMT10X,1),
	252:(0xfc,'unused','fmt10x',FMT10X,1),
	253:(0xfd,'unused','fmt10x',FMT10X,1),
	254:(0xfe,'unused','fmt10x',FMT10X,1),
	255:(0xff,'unused','fmt10x',FMT10X,1),
}


if __name__ == "__main__":
	buffer="\x12\x01\x6a\x01\xc3\x00\x22\x00\x23\x00\x54\x31\x45\x00\x00\x00\x00\x00"
	print parse_instruction(buffer)