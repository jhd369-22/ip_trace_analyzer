#!/usr/bin/env python3

import sys
import struct
import socket
import statistics
#import pdb;pdb.set_trace()

class IP_Header:  # reference from basic_structures.py
    
    
    def __init__(self,buffer):
        self.src_ip = None #<type 'str'>
        self.dst_ip = None #<type 'str'>
        self.ip_header_len = 0 #<type 'int'>
        self.total_len = 0    #<type 'int'>
        self.identification = 0    #<type 'int'>
        self.flags = {"RB": 0,"DF": 0,"MF": 0}     #<type 'dictionary'>
        self.fragment_offset = 0     #<type 'int'>
        self.TTL = 0     #<type 'int'>
        self.protocol = 0     #<type 'int'>
        self.setting(buffer)
    
    def setting(self,buffer):
        
        self.set_header_len(buffer[0:1])
        self.set_total_len(buffer[2:4])
        self.set_identification(buffer[4:6])
        self.set_flags(buffer[6:7])
        self.set_fragment_offset(buffer[6:7],buffer[7:8])
        self.set_TTL(buffer[8:9])
        self.set_protocol(buffer[9:10])
        self.set_IP(buffer[12:16],buffer[16:20])
    
    def get_ip(self):
        return [self.src_ip,self.dst_ip]
    
    def get_header_len(self):
        return self.ip_header_len
    
    def get_total_len(self):
        return self.total_len
        
    def get_identification(self):
        return self.identification
        
    def get_flag(self):
        return self.flags
        
    def get_fragment_offset(self):
        return self.fragment_offset
        
    def get_TTL(self):
        return self.TTL
        
    def get_protocol(self):
        return self.protocol
        
    def set_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.src_ip = s_ip
        self.dst_ip = d_ip
        #print("s_ip",s_ip)
        #print("d_ip",d_ip)
        
    def set_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.ip_header_len = length
        #print("length",length)

    def set_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len = length
        #print("total",length)
        
    def set_identification(self,value):
        self.identification = struct.unpack('>H', value)[0]
        
    def set_flags(self,value):                                        # in binary
        result = struct.unpack('B', value)[0]                         # RB DF MF
        self.flags["RB"] = (result & 128) >> 7 # Reserved bit         #  0  x  x x x x x x
        self.flags["DF"] = (result & 64) >> 6  # Dont fragment
        self.flags["MF"] = (result & 32) >> 5  # More fragment
        
    def set_fragment_offset(self,value1,value2):     # in binary                                            x x x x x x x x
        result1 = struct.unpack('B', value1)[0]      # RB DF MF            =>             =>    + x x x x x 0 0 0 0 0 0 0 0
        result2 = struct.unpack('B', value2)[0]      #  0  x  x x x x x x      x x x x x        *                         8
        self.fragment_offset = (((result1 & 31) << 8) + result2) * 8
        
    def set_TTL(self,value): 
        self.TTL = struct.unpack('B', value)[0]
        
    def set_protocol(self,value):
        self.protocol = struct.unpack('B', value)[0]
   

class UDP_Header:
    
    def __init__(self):
        self._src_port = 0
        self._dst_port = 0
        self._length = 0
        self._checksum = 0
        self._DNS_qdcount = None
        
    def __init__(self,buffer):
        self.ports = buffer[0:4]
        if(len(buffer) > 8):
            self.DNS_qdcount = buffer[12:14]
        if (packet.trace_type == None):
            packet.trace_type = "linux"
        
    @property    
    def ports(self):
        return [self._src_port,self._dst_port]
    @ports.setter
    def ports(self,value):
        self._src_port = struct.unpack(">H", value[0:2])[0]
        self._dst_port = struct.unpack(">H", value[2:4])[0]
    @property 
    def DNS_qdcount(self):
        return self._DNS_qdcount
    @DNS_qdcount.setter
    def DNS_qdcount(self,value):
        self._DNS_qdcount = struct.unpack(">H", value)[0]


class Win_ICMP_Header:
    
    def __init__(self):
        self._type = None # int
        self._code = None # int
        self._checksum = 0 # int
        self._seq_num = 0 # int
        self.p_ip_header = None
        self.p_icmp_header = None
    
    def __init__(self,buffer):
        self.type_ = buffer[0:1]
        self.code = buffer[1:2]
        self.seq_num = buffer[6:8]
        if(len(buffer) >= 36):
            self.p_ip_header = IP_Header(buffer[8:28])
            self.p_icmp_header = Win_ICMP_Header(buffer[28:])
        else:
            self.p_ip_header = None
            self.p_icmp_header = None
    @property    
    def type_(self):
        return self._type
        
    @type_.setter
    def type_(self,value):
        self._type = struct.unpack("B", value)[0]
        if (packet.trace_type == None and self.type_ == 8):
            packet.trace_type = "win"
    @property
    def code(self):
        return self._code    
    @code.setter
    def code(self,value):
        self._code = struct.unpack("B", value)[0]
    @property
    def seq_num(self):
        return self._seq_num    
    @seq_num.setter
    def seq_num(self,value):
        self._seq_num = struct.unpack(">H", value)[0]
    def set_p_ip_header(self,buffer):
        self.p_ip_header = IP_Header(buffer)
    def set_p_icmp_header(self,buffer):
        self.p_icmp_header = Win_ICMP_Header(buffer)


    
class Linux_ICMP_Header:
    
    def __init__(self):
        self._type = None # int
        self._code = None # int
        self._checksum = 0 # int
        self.p_ip_header = None
        self.p_udp_header = None
    
    def __init__(self,buffer):
        self.type_ = buffer[0:1]
        self.code = buffer[1:2]
        if(len(buffer) >= 36):
            self.p_ip_header = IP_Header(buffer[8:28])
            self.p_udp_header = UDP_Header(buffer[28:])
        else:
            self.p_ip_header = None
            self.p_udp_header = None
    @property    
    def type_(self):
        return self._type
        
    @type_.setter
    def type_(self,value):
        self._type = struct.unpack("B", value)[0]
        if (packet.trace_type == None and self.type_ == 8):
            packet.trace_type = "win"
    @property
    def code(self):
        return self._code    
    @code.setter
    def code(self,value):
        self._code = struct.unpack("B", value)[0]
    def set_p_ip_header(self,buffer):
        self.p_ip_header = IP_Header(buffer)
    def set_p_udp_header(self,buffer):
        self.p_udp_header = UDP_Header(buffer)
        

class packet:  # reference from basic_structures.py
    
    trace_type= None    # win or linux
    
    def __init__(self):
        self.IP_header = None
        self.TCP_header = None
        self.ICMP_header = None
        self.UDP_header = None
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.incl_len=0
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)
    def set_IP_header(self,buffer):
        self.IP_header = IP_Header(buffer)
    def set_TCP_header(self,tcph,buffer):
        self.TCP_header = TCP_Header(tcph,buffer)
    def set_Win_ICMP_header(self,buffer):
        self.ICMP_header = Win_ICMP_Header(buffer)
    def set_Linux_ICMP_header(self,buffer):
        self.ICMP_header = Linux_ICMP_Header(buffer)
    def set_UDP_header(self,buffer):
        self.UDP_header = UDP_Header(buffer)
        
    def get_timestamp(self):
        return self.timestamp
        
    def get_incl_len(self):
        return self.incl_len
        
    def get_RTT_value(self,p):
        rtt = self.timestamp - p.timestamp     #
        self.RTT_value = round(rtt,8)

    def set_incl_len(self,buffer):
        self.incl_len=struct.unpack('I',buffer)[0]


class Traceroute:
    
    def __init__(self):
        self._src_node = 0
        self._dst_node = 0
        self._node_list = []
        self._protocol_list = []
        self._fragments_list = []
        self._offset_list = []
        self._RTT_list = {}
    @property
    def nodes(self):
        return [self._src_node,self._dst_node]
    @nodes.setter
    def nodes(self,value):
        self._src_node = value[0]
        self._dst_node = value[1]
    @property
    def node_list(self):
        return self._node_list
    @node_list.setter
    def node_list(self,value):
        self._node_list = value
    @property
    def protocol_list(self):
        return self._protocol_list
    @protocol_list.setter
    def protocol_list(self,value):
        self._protocol_list = value
    @property
    def fragments_list(self):
        return self._fragments
    @fragments_list.setter
    def fragments_list(self,value):
        self._fragments = value
    @property
    def offset_list(self):
        return self._offset_list
    @offset_list.setter
    def offset_list(self,value):
        self._offset_list = value
    @property
    def RTT_list(self):
        return self._RTT_list
    @RTT_list.setter
    def RTT_list(self,value):
        self._RTT_list = value
    

def global_header(header):  # read global header info
    big_endian='>'
    little_endian='<'
    global_info={"endianness":None,"thiszone":None,"smaplen":None,"orig_time":None}
    
    magic_num=header[0:4]

    if(magic_num==b'\xd4\xc3\xb2\xa1'):   # extract endianness
        endianness=little_endian
    else:
        endianness=big_endian

    global_info["endianness"]=endianness
    #global_info["thiszone"]=header[8:12]
    #global_info["smaplen"]=header[16:20]

    
    return global_info


def readfile(): # read cap file, extract info base on the byte order
    packet_list=[]
    nextpacket=16
    current_packet=-1
    first = 0  #

    if len(sys.argv)==2:
        try:
            file=open(sys.argv[1],"rb")
        except:
            print("File cannot open!!")
            exit(1)

    global_info=global_header(file.read(24))

    while(True):
        ph=file.read(nextpacket)  # packet header

        if not ph:
            break

        current_packet+=1
        #packet_list.append(packet())
        tmp = packet()

        if(first==0):
            seconds = struct.unpack('I',ph[0:4])[0]
            microseconds = struct.unpack('<I',ph[4:8])[0]
            global_info["orig_time"] = round(seconds+microseconds*0.000000001,6)
            first+=1 #
        else:
            tmp.timestamp_set(ph[0:4],ph[4:8],global_info["orig_time"])
        
        tmp.set_incl_len(ph[8:12])
        pd=file.read(tmp.get_incl_len())  # packet data incl_len

        # read IP header
        tmp.set_IP_header(pd[14:])
        
        
        # read TCP info
        '''
        tcph=14+tmp.IP_header.get_header_len()
        tmp.set_TCP_header(tcph,pd)
        '''
        '''
        tmp.TCP_header.set_src_port(pd[tcph:tcph+2])
        tmp.TCP_header.set_dst_port(pd[tcph+2:tcph+4])
        tmp.TCP_header.set_seq_num(pd[tcph+4:tcph+8])
        tmp.TCP_header.set_data_offset(pd[tcph+12:tcph+13])
        tmp.TCP_header.set_flags(pd[tcph+13:tcph+14]) #
        tmp.TCP_header.set_window_size(pd[tcph+14:tcph+15],pd[tcph+15:tcph+16])
        
        if tmp.TCP_header.get_flags()["ACK"]==1:
            tmp.TCP_header.set_ack_num(pd[tcph+8:tcph+12])
        '''
        next_h=14+tmp.IP_header.get_header_len() # pass through the Ethernet hrader and IP header
        
        if(tmp.IP_header.get_protocol() == 17 and packet.trace_type != "win"): # UDP
            tmp.set_UDP_header(pd[next_h:])    
            if(tmp.UDP_header.DNS_qdcount == 1):
                current_packet-=1
                continue
            '''
            if((tmp.UDP_header.ports[1] < 33434) or (tmp.UDP_header.ports[1] > 33529)):  # filter out the irrelevant UDP packets
                current_packet-=1
                continue
            '''
        elif(tmp.IP_header.get_protocol() == 1): # ICMP
            if(packet.trace_type == "linux"):
                tmp.set_Linux_ICMP_header(pd[next_h:])
            if(packet.trace_type == "win" or packet.trace_type == None):
                tmp.set_Win_ICMP_header(pd[next_h:])     
        else:
            current_packet-=1
            continue

        packet_list.append(tmp)
        
    file.close()
    return packet_list


def linux_traceroute(packet_list):
    nodes = []         # list of intermediate routers
    protocols = []     # list of protocols
    times = []         # times for each fragment
    fragments = []     # a list of number of fragments
    offset = []        # the last offset of each fragmentation
    match = 0          # to check if matching a new fragmentation
    new_traceroute = Traceroute() # a class to store info
    
    for i in packet_list:
        if(i.IP_header.get_protocol() not in protocols):   # eliminate duplicate protocol
            protocols.append(i.IP_header.get_protocol())
        if(i.IP_header.get_protocol() == 17):            # match UDP
            if((i.IP_header.get_flag()["MF"] == 0) and (i.IP_header.get_fragment_offset() == 0)):
                tmp_time = []
                tmp_time.append(i.get_timestamp())
            if((i.IP_header.get_flag()["MF"] == 1) and (i.IP_header.get_fragment_offset() == 0)): # to check if matching a new fragmentation
                #tmp_time = []
                count_frag = 1   # count number of fragment
                match = 1
                tmp_time.append(i.get_timestamp())
            if(new_traceroute.nodes == [0,0]):
                new_traceroute.nodes = i.IP_header.get_ip()
            for j in packet_list[packet_list.index(i)+1 :]:
                if(match == 1):      # check if there are more fragments
                    if(i.IP_header.get_identification() == j.IP_header.get_identification()):
                        count_frag+=1
                        tmp_time.append(j.get_timestamp())
                        if(j.IP_header.get_flag()["MF"] == 0): # matching the last fragment
                            fragments.append(count_frag)
                            offset.append([j.IP_header.get_identification(),j.IP_header.get_fragment_offset()])
                if((j.IP_header.get_protocol() == 1) and (j.ICMP_header.p_udp_header != None)): # match the reply from intermediate router
                    if(i.UDP_header.ports == j.ICMP_header.p_udp_header.ports):
                        tmp = j.IP_header.get_ip()[0]
                        if(match == 1):
                            match = 0
                        tmp_time.append(j.get_timestamp())
                        tmp_time.append(tmp)
                        times.append(tmp_time)
                        
                        if((tmp not in nodes) and (tmp != i.IP_header.get_ip()[1])):
                            nodes.append(tmp)
    
    RTT = {}
    for i in times:   # find each RTT
        for j in i[:-2]:
            if(i[-1] not in RTT):
                RTT[i[-1]] = []
            RTT[i[-1]].append((i[-2] - j)*1000)
            
    for i in RTT:     # find the mean and the standard deviation
        tmp = RTT[i]
        RTT[i] = [statistics.mean(tmp)]
        RTT[i].append(statistics.pstdev(tmp))
            
    
    new_traceroute.node_list = nodes
    new_traceroute.protocol_list = sorted(protocols)
    new_traceroute.RTT_list = RTT
    new_traceroute.fragments_list = fragments
    new_traceroute.offset_list = offset
    '''
    for i in RTT:
        print("address: "+i+" avg: "+str(RTT[i][0])+" std: "+str(RTT[i][1]))
        print()
    for i in range(0,len(fragments)):
        print("fragment: "+str(fragments[i]))
        print("offset: "+str(offset[i]))
    '''
    return new_traceroute
    
    
            
def win_traceroute(packet_list):
    nodes = []         # list of intermediate routers
    protocols = []     # list of protocols
    times = []         # times for each fragment
    fragments = []     # a list of number of fragments
    offset = []        # the last offset of each fragmentation
    match = 0          # to check if matching a new fragmentation
    new_traceroute = Traceroute() # a class to store info
    
    for i in packet_list:
        if(i.IP_header.get_protocol() not in protocols):   # eliminate duplicate protocol
            protocols.append(i.IP_header.get_protocol())
        if((i.IP_header.get_protocol() == 1) and (i.ICMP_header.type_ == 8)):        # match ICMP
            if((i.IP_header.get_flag()["MF"] == 0) and (i.IP_header.get_fragment_offset() == 0)):
                tmp_time = []
                tmp_time.append(i.get_timestamp())
            if((i.IP_header.get_flag()["MF"] == 1) and (i.IP_header.get_fragment_offset() == 0)): # to check if matching a new fragmentation
                #tmp_time = []
                count_frag = 1   # count number of fragment
                match = 1
                tmp_time.append(i.get_timestamp())
            if(new_traceroute.nodes == [0,0]):
                new_traceroute.nodes = i.IP_header.get_ip()
            for j in packet_list[packet_list.index(i)+1 :]:
                if(match == 1):      # check if there are more fragments
                    if(i.IP_header.get_identification() == j.IP_header.get_identification()):
                        count_frag+=1
                        tmp_time.append(j.get_timestamp())
                        if(j.IP_header.get_flag()["MF"] == 0): # matching the last fragment
                            fragments.append(count_frag)
                            offset.append([j.IP_header.get_identification(),j.IP_header.get_fragment_offset()])
                if((j.IP_header.get_protocol() == 1) and (j.ICMP_header.type_ != 8)): # match the reply from intermediate router
                    ## In windows,the last ICMP reply packet dont include the ICMP info of the previous request packet 
                    if((i.ICMP_header.seq_num == j.ICMP_header.p_icmp_header.seq_num) or (i.ICMP_header.seq_num == j.ICMP_header.seq_num)):
                        tmp = j.IP_header.get_ip()[0]
                        if(match == 1):
                            match = 0
                        tmp_time.append(j.get_timestamp())
                        tmp_time.append(tmp)
                        times.append(tmp_time)
                        
                        if((tmp not in nodes) and (tmp != i.IP_header.get_ip()[1])):
                            nodes.append(tmp)
    
    RTT = {}
    for i in times:   # find each RTT
        for j in i[:-2]:
            if(i[-1] not in RTT):
                RTT[i[-1]] = []
            RTT[i[-1]].append((i[-2] - j)*1000)
            
    for i in RTT:     # find the mean and the standard deviation
        tmp = RTT[i]
        RTT[i] = [statistics.mean(tmp)]
        RTT[i].append(statistics.pstdev(tmp))
            
    
    new_traceroute.node_list = nodes
    new_traceroute.protocol_list = sorted(protocols)
    new_traceroute.RTT_list = RTT
    new_traceroute.fragments_list = fragments
    new_traceroute.offset_list = offset
    
    return new_traceroute
    

def display(new_traceroute):
    print("The IP address of the source node: "+new_traceroute.nodes[0])
    print("The IP address of ultimate destination node: "+new_traceroute.nodes[1])
    print("The IP addresses of the intermediate destination nodes:")
    count = 0
    for i in new_traceroute.node_list:
        count += 1
        print("router "+str(count)+": "+i)
        
    print()
    
    print("The values in the protocol field of IP headers:")
    for i in new_traceroute.protocol_list:
        if(i == 1):
            print(str(i)+": ICMP")
        elif(i == 17):
            print(str(i)+": UDP")
            
    print()
    
    for i in range(0,len(new_traceroute.fragments_list)):
        print("The number of fragments created from the original datagram "+\
        str(new_traceroute.offset_list[i][0])+" is: "+str(new_traceroute.fragments_list[i]))
        print("The offset of the last fragment is: "+str(new_traceroute.offset_list[i][1]))
        print()
        
    for i in new_traceroute.RTT_list:
        print("The avg RTT between "+new_traceroute.nodes[0]+" and "+i+\
        " is: "+str(round(new_traceroute.RTT_list[i][0],3))+\
        " ms, the s.d. is: "+str(round(new_traceroute.RTT_list[i][1],3))+" ms")
    
def main():
    packet_list = readfile()     # read cap file infomation
    
    if(packet.trace_type == "linux"):
        new_traceroute = linux_traceroute(packet_list)
    else:
        new_traceroute = win_traceroute(packet_list)
    
    display(new_traceroute)


if __name__ == "__main__":
    main()
