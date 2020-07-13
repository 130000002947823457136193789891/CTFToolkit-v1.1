#coding:utf-8

import struct
import binascii
import hashlib
import zlib
 
class DexFile:
    def __init__(self,filepath):
        self.dex = open(filepath,"r")
        self.strings = []
        self.types = []
        self.protos = []
        self.fields = []
        self.method = []
        self.map_type = {0x0:"header_item",
                     0x1:"string_id_item",
                     0x2:"type_id_item",
                     0x3:"proto_id_item",
                     0x4:"field_id_item",
                     0x5:"method_id_item",
                     0x6:"class_def_item",
                     0x1000:"map_list",
                     0x1001:"type_list",
                     0x1002:"annotation_set_ref_list",
                     0x1003:"annotation_set_item",
                     0x2000:"class_data_item",
                     0x2001:"code_item",
                     0x2002:"string_data_item",
                     0x2003:"debug_info_item",
                     0x2004:"annotation_item",
                     0x2005:"encoded_array_item",
                     0x2006:"annotations_directory_item"}
        
        
    def ReadDexHeader(self):
        print "----------------解析 DexHeader-----------------------------"
        self.magic = struct.unpack("4s",self.dex.read(4))[0]
        print "magic code:",self.magic,#加逗号去掉最后的自动换行        
        if self.magic != "dex\n":
            print "the file is not a dex file"
            self.CloseDexFile()
            exit(-1)
            return
            
        self.version = struct.unpack("4s",self.dex.read(4))[0]
        print "version:",self.version
        
        #用adler32算法对这个字段之后的所有数据做的检验码，来验证这个dex文件是否损坏
        self.checksum = struct.unpack("i",self.dex.read(4))[0]       
        print "checksum:",self.checksum
 
        #dex文件的签名值（是对这个字段之后的所有数据做的签名，用来唯一的标识这个dex文件）        
        self.sig = struct.unpack("20s",self.dex.read(20))[0]
        #将字符串以16进制打印出时用 binascii库  
        print "signature:", str(binascii.b2a_hex(self.sig))        
        
        
        self.filesize = struct.unpack("I",self.dex.read(4))[0]  
        print "filesize:",self.filesize
 
        self.headersize = struct.unpack("I",self.dex.read(4))[0]  
        print "headersize:",self.headersize
        
        #默认情况下是以小顶端的方式存 小顶端时读出0x12345678,大顶端时读出0x78563412
        self.endiantag = struct.unpack("I",self.dex.read(4))[0]  
        print "endiantag:",hex(self.endiantag)
        
        self.link_size = struct.unpack("I",self.dex.read(4))[0]  
        print "link_size:",self.link_size
        
        self.link_off = struct.unpack("I",self.dex.read(4))[0]  
        print "link_off:",self.link_off,"(",hex(self.link_off),")"
        
        self.map_off = struct.unpack("I",self.dex.read(4))[0]  
        print "map_off:",self.map_off,"(",hex(self.map_off),")"
        
        self.string_num = struct.unpack("I",self.dex.read(4))[0]  
        print "string_num:",self.string_num
        
        self.string_table_off = struct.unpack("I",self.dex.read(4))[0]  
        print "string_table_off:",self.string_table_off,"(",hex(self.string_table_off),")"
        
        self.type_num = struct.unpack("I",self.dex.read(4))[0]  
        print "type_num:",self.type_num
        
        self.type_table_off = struct.unpack("I",self.dex.read(4))[0]  
        print "type_table_off:",self.type_table_off,"(",hex(self.type_table_off),")"
        
        self.proto_num = struct.unpack("I",self.dex.read(4))[0]  
        print "proto_num:",self.proto_num
        
        self.proto_off = struct.unpack("I",self.dex.read(4))[0]  
        print "proto_off:",self.proto_off,"(",hex(self.proto_off),")"
                
        self.field_num = struct.unpack("I",self.dex.read(4))[0]  
        print "field_num:",self.field_num
        
        self.field_off = struct.unpack("I",self.dex.read(4))[0]  
        print "field_off:",self.field_off,"(",hex(self.field_off),")"
        
        self.method_num = struct.unpack("I",self.dex.read(4))[0]  
        print "method_num:",self.method_num
        
        self.method_off = struct.unpack("I",self.dex.read(4))[0]  
        print "method_off:",self.method_off,"(",hex(self.method_off),")"
        
        self.class_def_size = struct.unpack("I",self.dex.read(4))[0]  
        print "class_def_size:",self.class_def_size      
        
        self.class_def_off = struct.unpack("I",self.dex.read(4))[0]  
        print "class_def_off:",self.class_def_off,"(",hex(self.class_def_off),")"
 
        self.data_size = struct.unpack("I",self.dex.read(4))[0]  
        print "data_size:",self.data_size
        
        self.data_off = struct.unpack("I",self.dex.read(4))[0]  
        print "data_off:",self.data_off,"(",hex(self.data_off),")"
        
   
            
    def CalSignature(self):
        #4 + 4 + 4 + 20
        self.dex.seek(32)
        sigdata = self.dex.read()
        sha1 = hashlib.sha1()
        sha1.update(sigdata)
        print "signature:",sha1.hexdigest()
    
    def CalChecksum(self):
        self.dex.seek(12)
        checkdata = self.dex.read()
        checksum = zlib.adler32(checkdata)
        print "checksum:",checksum
    
    
    
    def DecUnsignedLEB128(self,file):
        result = struct.unpack("i", file.read(4))[0]
        result = result&0x000000ff  
        file.seek(-3, 1)  # 不能直接从1字节强转为4字节，所以先取4字节，再清空3字节
        if(result > 0x7f):
            next = struct.unpack("i", file.read(4))[0]
            next = next&0x000000ff
            file.seek(-3, 1)
            result = (result&0x7f) | (next&0x7f)<<7
            if(next > 0x7f):
                next = struct.unpack("i", file.read(4))[0]
                next = next&0x000000ff
                file.seek(-3, 1)
                result = result | (next&0x7f)<<14
                if(next > 0x7f):
                    next = struct.unpack("i", file.read(4))[0]
                    next = next&0x000000ff
                    file.seek(-3, 1)
                    result = result | (next&0x7f)<<21
                    if(next > 0x7f):
                        next = struct.unpack("i", file.read(4))[0]
                        next = next&0x000000ff
                        file.seek(-3, 1)
                        result = result | next<<28
                        
        #print "result:", result
        return result    
    
    
    def CloseDexFile(self):
        self.dex.close()
            
 
 
 
if __name__ == "__main__":
    df = DexFile("classes.dex") 
    df.ReadDexHeader()
    df.CalSignature()
    df.CalChecksum()
    df.CloseDexFile()