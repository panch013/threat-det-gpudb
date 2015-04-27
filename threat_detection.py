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
  cmd = "tcpdump -nS -c100 -w " + traffic_cap 
  os.system(cmd)  

# TODO: make gpudb_ip an argument
def add_data(traffic_data):
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
  
  retobj = gpudb.do_register_type(type_definition,"","point-type","POINT")
  type_id = retobj['type_id']
  
  set_id = str(uuid.uuid1())
  retobj = gpudb.do_new_set(type_id,set_id)
 
  x = 1;y = 1 
  encoded_datums = []
  for e in traffic_data: 
    datum = ordereddict.OrderedDict([('x',x), ('y',y), ('src',e[0]),('dst',e[1]),('payload',e[2])])
    encoded_datum = gpudb.encode_datum(type_definition,datum)
    encoded_datums.append(encoded_datum)
    x+=1;y+=1
     
  gpudb.do_bulk_add(set_id, encoded_datums)

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

  '''
  Transform pcap fields into json 
  objects and store it in GPUdb  
  '''
  # TODO: read pcap file and transform the data 
  traffic_data = convert_traffic(traffic_cap)

  # TODO: Add Data to GPUdb
  set_id, gpudb = add_data(traffic_data)
  print "Data stored at GPUdb"

  # Query GPUdb server
  query(set_id, gpudb)
 
  # TODO: Record Stats of the query
  print 'Sats Recorded in the file: "', stats


#TODO: make packet capture real time
# callback function - called for every packet
def traffic_monitor_callbak(pkt):
    if IP in pkt:
        print pkt.sprintf("%IP.len%")

# capture traffic for 10 seconds
def capture_traffic_rt(traffic_cap):
  sniff(iface="eth0", prn=traffic_monitor_callbak, store=0, timeout=10)
if __name__ == "__main__":
   main(sys.argv[1:])
