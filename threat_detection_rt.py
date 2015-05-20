'''
TODO: Add more information
Threat Detection using tcpdump

'''
# In-built python packages
import os, time, sys, getopt
'''
Strange: collections does not have the module - 'OrderedDict' in python 2.6.9
Use ordereddict instead
'''
'''
if sys.version_info >= (2, 7):
    import collections
else:
    import ordereddict as collections
'''
import ordereddict
import sys
reload(sys)
#sys.setdefaultencoding('utf-8')
sys.setdefaultencoding('iso-8859-1')
# Traffic capture packages
import dpkt
#from scapy.all import sr1,IP,ICMP,rdpcap
from scapy.all import *

# GPUdb packages
from gpudb import GPUdb
import uuid #for generating uuids



gpudb = GPUdb(encoding='BINARY',gpudb_ip='10.1.10.31',gpudb_port='9191')
# Add more fileds as needed for the analysis  
type_definition = """{
                       "type":"record",
                       "name":"gen_pt",
                       "fields":[
                           {"name":"x","type":"double"},
                           {"name":"y","type":"double"},
                           {"name":"src","type":"string"},
                           {"name":"dst","type":"string"},
                           {"name":"payload","type":"string"}
                        ]
                     }"""

# TODO : Pass pcap file as input
def print_packet_stats():
  print "Total number of packets in the pcap file: ", counter
  print "Total number of ip packets: ", ipcounter
  print "Total number of tcp packets: ", tcpcounter
  print "Total number of udp packets: ", udpcounter  


# Global counters
counter = 0; ipcounter = 0; tcpcounter = 0; udpcounter = 0
def count_packets(traffic_cap):
  
  for ts, pkt in dpkt.pcap.Reader(open(traffic_cap, 'r')):
      counter+=1
      eth=dpkt.ethernet.Ethernet(pkt) 
      if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
         continue
      ip=eth.data
      ipcounter+=1
      if ip.p==dpkt.ip.IP_PROTO_TCP: 
         tcpcounter+=1
  
      if ip.p==dpkt.ip.IP_PROTO_UDP:
         udpcounter+=1

  print_packet_stats() 


def convert_traffic(traffic_cap):
  #raw_data = rdpcap("traffic")
  #print raw_data
  traffic_data = list((p[IP].src, p[IP].dst, (str(p[IP].payload)).encode('utf-8').strip()) for p in PcapReader(traffic_cap) if IP in p)
  return traffic_data


#TODO add support for providing more options to tcpudump
def capture_traffic(traffic_cap):
  cmd = "tcpdump -nS -c10 -w " + traffic_cap 
  os.system(cmd)  

# TODO: make gpudb_ip an argument
def add_data():


  return set_id,gpudb
  
# Query GPUdb
# TODO: define different machine learning queries
def query(set_id, gpudb):
  print "Querying ..."
  lower_bound = 1; upper_bound = 1
  attribute_key = "x"
  result_set_id = str(uuid.uuid1())
  # Bounding Box Query
  retobj = gpudb.do_filter_by_bounds(set_id, lower_bound, attribute_key, upper_bound, result_set_id)
  print retobj

def main(argv):
  traffic_cap = ''
  stats = ''
  try:
     opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
  except getopt.GetoptError:
     print 'threat_detection.py -i <traffic_cap> -o <stats>'
     sys.exit(2)
  for opt, arg in opts:
     if opt == '-h':
        print 'threat_detection.py -i <traffic_cap> -o <stats>'
        sys.exit()
     elif opt in ("-i", "--ifile"):
        traffic_cap = arg
     elif opt in ("-o", "--ofile"):
        stats = arg

  try:
    tc = open(traffic_cap)
    print "Traffic was already captured in the file: ", traffic_cap 
    # Count packets 
    # count_packets(traffic_cap)
  except IOError:
    print traffic_cap + " not present. Capturing Traffic ..."
    # Capture Packets in a pcap file.
    capture_traffic(traffic_cap)
    print 'Traffic Captured in the file: ', traffic_cap
    # Count packets 
    # count_packets(traffic_cap)

  print 'Collecting Traffic in real time'
  '''
  Transform pcap fields into json 
  objects and store it in GPUdb  
  '''
  capture_traffic_rt()
  print "Data stored at GPUdb"

  # Query GPUdb server
  #query(set_id, gpudb)
 
  retobj = gpudb.do_clear("")
  print "Cleared all the sets"


#TODO: make packet capture real time
# callback function - called for every packet
retobj = gpudb.do_register_type(type_definition,"","point-type","POINT")
type_id = retobj['type_id']

set_id = str(uuid.uuid1())
retobj = gpudb.do_new_set(type_id,set_id)
x = 1;y = 1 

def traffic_monitor_callback(p):
  global x; global y 
  if IP in p:
    datum = ordereddict.OrderedDict([('x',x), ('y',y), ('src',p[IP].src),('dst',p[IP].dst),('payload',(str(p[IP].payload)).encode('utf-8').strip())])
    encoded_datum = gpudb.encode_datum(type_definition,datum)
    gpudb.do_add(set_id, encoded_datum)
    x+=1;y+=1

# capture traffic for 10 seconds
def capture_traffic_rt():
  #sniff(iface="eth0", prn=traffic_monitor_callbak, store=0, timeout=10)
  sniff(iface="eth0", prn=traffic_monitor_callback, store=0, count=100)

if __name__ == "__main__":
   main(sys.argv[1:])
