import Network_2_1
import argparse
from time import sleep
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32
    
    ack="ACK"
    def __init__(self, seq_num, msg_S, ack2):
        self.ack=ack2
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        #if Packet.corrupt(byte_S):
            #raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S, self.ack)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S
        

class RDT:
    ## latest sequence number used in a packet
    seq_num = 0
    ## buffer of bytes read from network
    byte_buffer = ''
    
    stateR=1
    statesend=1
    counter=0
    def __init__(self, role_S, server_S, port):
        self.network = Network_2_1.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
            
    def changeState(self):
        if(self.seq_num==0):
            self.seq_num=1
        else:
            self.seq_num=0
            
    def rdt_2_1_send(self, msg_S):

        # If packet is corrupted or we received NAK 1
        if (self.statesend==2):
            ret_S = None
            byte_S = self.network.udt_receive()
            self.byte_buffer += byte_S
            
            #keep extracting packets - if reordered, could get more than one
            while True:
                byte_S = self.network.udt_receive()
                self.byte_buffer += byte_S
                #check if we have received enough bytes
                if(len(self.byte_buffer) >= Packet.length_S_length):
                    length = int(self.byte_buffer[:Packet.length_S_length])
                    if len(self.byte_buffer) >= length:
                        p = Packet.from_byte_S(self.byte_buffer[0:length])
                        #remove the packet bytes from the buffer
                        
                        #if this was the last packet, will return on the next iteration
                        if((p.corrupt(self.byte_buffer[0:length]) or p.ack=="NAK")):
                            self.byte_buffer = self.byte_buffer[length:]
                            self.network.udt_send(p.get_byte_S())
                        else:
                            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                            self.byte_buffer = self.byte_buffer[length:]
                            self.statesend=1
                            return
        # If packet is corrupted or we received NAK 2     
        elif (self.statesend==4):
            ret_S = None
            byte_S = self.network.udt_receive()
            self.byte_buffer += byte_S
            while True:
                byte_S = self.network.udt_receive()
                self.byte_buffer += byte_S
                #keep extracting packets - if reordered, could get more than one
                #check if we have received enough bytes
                if(len(self.byte_buffer) >= Packet.length_S_length):
                    length = int(self.byte_buffer[:Packet.length_S_length])
                    if len(self.byte_buffer) >= length:
                        p = Packet.from_byte_S(self.byte_buffer[0:length])
                        #remove the packet bytes from the buffer
                        #if this was the last packet, will return on the next iteration        
                        if((p.corrupt(self.byte_buffer[0:length]) or p.ack=="NAK")):
                            self.byte_buffer = self.byte_buffer[length:]
                            self.network.udt_send(p.get_byte_S())
                        else:
                            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                            self.byte_buffer = self.byte_buffer[length:]
                            self.changeState()
                            self.statesend=1
                            return

                
        if (self.statesend==3): #wait for call from appl 2

            self.seq_num = 0
            seq_num_S = str(self.seq_num).zfill(Packet.seq_num_S_length)
            #convert length to a byte field of length_S_length bytes
            length_S = str(Packet.length_S_length + len(seq_num_S) + Packet.checksum_length + len(msg_S)).zfill(Packet.length_S_length)
            checksum = hashlib.md5((length_S+seq_num_S+msg_S).encode('utf-8'))
            checksum_S = checksum.hexdigest()
            p = Packet(self.seq_num, msg_S, checksum_S)
            self.statesend=4
            self.network.udt_send(p.get_byte_S())

        elif(self.statesend==1): #wait for call from appl 1
            if (self.counter==1):
                self.changeState()
            self.changeState()
            self.counter==1
            seq_num_S = str(self.seq_num).zfill(Packet.seq_num_S_length)
            #convert length to a byte field of length_S_length bytes
            length_S = str(Packet.length_S_length + len(seq_num_S) + Packet.checksum_length + len(msg_S)).zfill(Packet.length_S_length)
            checksum = hashlib.md5((length_S+seq_num_S+msg_S).encode('utf-8'))
            checksum_S = checksum.hexdigest()
            p = Packet(self.seq_num, msg_S, checksum_S)
            self.statesend=2
            self.network.udt_send(p.get_byte_S())
            

        
    
            
    def rdt_2_1_receive(self):
        
        if (self.stateR==1):
            ret_S = None
            byte_S = self.network.udt_receive()
            self.byte_buffer += byte_S
            while True:
               
                #check if we have received enough bytes
                if(len(self.byte_buffer) < Packet.length_S_length):
                    return ret_S #not enough bytes to read packet length
                #extract length of packet
                length = int(self.byte_buffer[:Packet.length_S_length])
                if len(self.byte_buffer) < length:
                    return ret_S #not enough bytes to read the whole packet
                #create packet from buffer content and add to return string
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                #remove the packet bytes from the buffer
                
                #if this was the last packet, will return on the next iteration
                if ((not p.corrupt(self.byte_buffer[0:length])) and p.seq_num==0):
                    sndpkt=Packet(p.seq_num, p.msg_S, "ACK")
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.byte_buffer = self.byte_buffer[length:]
                    self.network.udt_send(sndpkt.get_byte_S())
                    return ret_S
                    
                elif (p.corrupt(self.byte_buffer[0:length])):
                    sndpkt=Packet(p.seq_num, p.msg_S,"NAK")
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.byte_buffer = self.byte_buffer[length:]
                    self.network.udt_send(sndpkt.get_byte_S())
                    return ret_S

                elif((not p.corrupt(self.byte_buffer[0:length])) and p.seq_num==1):
                    while True:
                        #check if we have received enough bytes
                        if(len(self.byte_buffer) < Packet.length_S_length):
                            return ret_S #not enough bytes to read packet length
                        #extract length of packet
                        length = int(self.byte_buffer[:Packet.length_S_length])
                        if len(self.byte_buffer) < length:
                            return ret_S #not enough bytes to read the whole packet
                        #create packet from buffer content and add to return string
                        p = Packet.from_byte_S(self.byte_buffer[0:length])
                        #if this was the last packet, will return on the next iteration
                        #remove the packet bytes from the buffer
                        self.stateR=2
                        ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                        self.byte_buffer = self.byte_buffer[length:]
                        checksum_S = self.byte_buffer[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
                        sndpkt=Packet(p.seq_num, checksum_S,"ACK")   
                        self.network.udt_send(sndpkt.get_byte_S())
                                    
        if(self.stateR==2):
            ret_S = None
            byte_S = self.network.udt_receive()
            self.byte_buffer += byte_S
            while True:
                
                #check if we have received enough bytes
                if(len(self.byte_buffer) < Packet.length_S_length):
                    return ret_S #not enough bytes to read packet length
                #extract length of packet
                length = int(self.byte_buffer[:Packet.length_S_length])
                if len(self.byte_buffer) < length:
                    return ret_S #not enough bytes to read the whole packet
                #create packet from buffer content and add to return string
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                
                #if this was the last packet, will return on the next iteration
                #remove the packet bytes from the buffer
                #print(p.seq_num)
                if ((not p.corrupt(self.byte_buffer[0:length])) and p.seq_num==1):
                    sndpkt=Packet(p.seq_num, p.msg_S, "ACK")
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.byte_buffer = self.byte_buffer[length:]
                    self.network.udt_send(sndpkt.get_byte_S())
                    return ret_S
                    
                elif (p.corrupt(self.byte_buffer[0:length])):
                    sndpkt=Packet(p.seq_num, p.msg_S,"NAK")
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.byte_buffer = self.byte_buffer[length:]
                    self.network.udt_send(sndpkt.get_byte_S())
                    return ret_S

                elif((not p.corrupt(self.byte_buffer[0:length])) and p.seq_num==0):
                    while True:
                        #check if we have received enough bytes
                        if(len(self.byte_buffer) < Packet.length_S_length):
                            return ret_S #not enough bytes to read packet length
                        #extract length of packet
                        length = int(self.byte_buffer[:Packet.length_S_length])
                        if len(self.byte_buffer) < length:
                            return ret_S #not enough bytes to read the whole packet
                        #create packet from buffer content and add to return string
                        p = Packet.from_byte_S(self.byte_buffer[0:length])
                        ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                        #if this was the last packet, will return on the next iteration
                        #remove the packet bytes from the buffer
                        self.byte_buffer = self.byte_buffer[length:]
                        self.stateR=1
                        checksum_S = self.byte_buffer[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
                        sndpkt=Packet(p.seq_num, checksum_S,"ACK")
                        self.network.udt_send(sndpkt.get_byte_S())
                        
                        
    
    def rdt_3_0_send(self, msg_S):
        pass
        
    def rdt_3_0_receive(self):
        pass
        

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
