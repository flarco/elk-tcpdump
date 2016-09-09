import sys, os, re, time, datetime, threading, socket, json
from subprocess import Popen, PIPE, STDOUT
from collections import namedtuple, OrderedDict
import linecache, traceback


args = sys.argv[1:]
utc_delta = datetime.datetime.utcnow() - datetime.datetime.now()

if len(args) < 1:
  print('USAGE:                python tcpdump_aggregate.py "TARGET_IP:UDP_PORT"')
  print('EXAMPLE:              python tcpdump_aggregate.py "127.0.0.1:5141"')
  print('EXAMPLE with tcpdump: tcpdump -U -i eth0 -nn -tttt port not 5141 | python tcpdump_aggregate.py "127.0.0.1:5141"')
  sys.exit(1)


UDP_IP = args[0].split(':')[0]
UDP_PORT = int(args[0].split(':')[1])
SEC_INTERVAL = 20 # UDP send / Aggregate reset interval


def get_exception_message(append_message = ''):
  """Obtain and return exception message"""
  
  exc_type, exc_obj, tb = sys.exc_info()
  f = tb.tb_frame
  lineno = tb.tb_lineno
  filename = f.f_code.co_filename
  linecache.checkcache(filename)
  line = linecache.getline(filename, lineno, f.f_globals)
  message = '-'*70 + '\n' +'EXCEPTION IN ({}, LINE {} "{}"): {} \n---\n{}'.format(filename, lineno, line.strip(), exc_obj, traceback.format_exc()) + '\n' + append_message
  return message


def run_command(command, show_output = False, input = ''):
  """Run a shell command and return the output"""
  
  process = Popen(command, shell=True, stdout=PIPE, stderr=STDOUT)
  
  stdout_array = []
  
  for line in iter(process.stdout.readline, ''):
    if show_output: sys.stdout.write(line)
    stdout_array.append(line.rstrip())
  
  process.wait()
  stdout = '\n'.join(stdout_array) + process.stdout.read()
  
  return stdout

def parse_ip_port(address):
  """Parse the IP and PORT from address string"""
  if ':' in address:
    # IP6
    deli = ":"
    
    if '.' in address: # there is PORT
      IP = address.split('.')[0]
      PORT = int(address.split('.')[-1])
    else: # there is no PORT
      IP = address
      PORT = ''
  else:
    # IP4
    deli = "."
    arr = address.split(deli)
    if len(arr) == 5:
      IP = deli.join(arr[:-1])
      PORT = int(arr[-1])
    else:
      IP = address
      PORT = ''
  
  return (IP, PORT)


host_cache = {}  # cache of IP to host mapping
threads = {}  # One thread per IP
thread_lock = threading.Lock()
command_lock = threading.Lock()

def get_host(IP):
  """Attempt to obtain the hostname of the IP, starts a thread."""
  global host_cache, threads, thread_lock
  with thread_lock:
    if IP in host_cache:
      return host_cache[IP]
  
  # kick off thread
  if not IP in threads:
    threads[IP] = threading.Thread(target=get_host_process, args = (IP,))
    threads[IP].start()
  
  return IP


def get_host_process(IP):
  """Tread to obtain the host name of the IP"""
  global host_cache, thread_lock
  with command_lock:
    # print('Getting host for ' + IP)
    host = run_command('host ' + IP).split()[-1][:-1] # remove dot at the end
  if 'XDOMAIN' in host:
    host = 'NXDOMAIN'
  with thread_lock:
    host_cache[IP] = host


def parse_packet(line):
  """
  Parse one packet and return a dictionary record with the following keys:
  source_IP, source_PORT, source_HOST,
  target_IP, target_PORT, target_HOST,
  length, type, flags, seq, ask, win
  """
  if not ', length ' in line: return
  if not '>' in line: return
  if 'ff:ff:ff:ff:ff:ff' in line: return
  
  packet = {}
  
  arr1 = line.split(' > ')
  part1 = arr1[0] # 2015-10-29 12:53:44.030124 IP 192.168.1.3.36409
  part1_arr = part1.split()
  
  arr2 = arr1[1].split(', length ')
  part2 = arr2[0] #  192.168.1.193.4849: UDP
  part2_arr = part2.split()
  
  source = part1_arr[-1]
  target = part2_arr[0][:-1]
  
  part3 = ' '.join(part2_arr[1:])
  part3_arr = part3.split(',')
  
  packet['length'] = int(re.sub("[^0-9]", "", arr2[1].split(":")[0].split()[0]))
  
  packet['time'] = datetime.datetime.strptime(' '.join(part1_arr[0:2]), '%Y-%m-%d %H:%M:%S.%f')
  
  if part3 == 'UDP':
    packet['type'] = 'UDP'
  else:
    packet['type'] = 'TCP'
  
  # convert to UTC time for MongoDB
  packet['time'] = packet['time'] + datetime.timedelta(seconds=round(utc_delta.total_seconds()))
  
  
  (packet['source_IP'], packet['source_PORT']) = parse_ip_port(source)
  (packet['target_IP'], packet['target_PORT']) = parse_ip_port(target)
  
  packet['source_HOST'] = get_host(packet['source_IP'])
    
  packet['target_HOST'] = get_host(packet['target_IP'])
  
  for k in 'flags seq ack win'.split():
    packet[k] = ''
  
  for p in part3_arr:
    p = p.strip()
    if p.startswith('Flags'): packet['flags'] = p.split()[-1]
    if p.startswith('seq'): packet['seq'] = p.split()[-1]
    if p.startswith('ack'): packet['ack'] = int(p.split()[-1])
    if p.startswith('win'): packet['win'] = int(p.split()[-1])
  
  return packet

  
class Packet_Aggregate:
  """An Aggregate of packets with the length/count fields summed.
  Also has the function to send the aggregate via UDP_IP
  to as Logstash destination"""
  
  UPD_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  combo_keys = 'source_IP source_PORT target_IP target_PORT type'.split()
  Combo = namedtuple('Combo', combo_keys)
  
  def __init__(self):
    self.combo_count = {}
    self.combo_length_sum = {}
    self.combo_host = {}
  
  def ingest(self, packet):
    combo_key = self.Combo(*[packet[key] for key in self.combo_keys])
    
    length = packet['length']
    self.combo_count[combo_key] = self.combo_count.get(combo_key, 0) + 1
    self.combo_length_sum[combo_key] = self.combo_length_sum.get(combo_key, 0) + length
    
    self.combo_host[combo_key] = dict(
      source_HOST = packet['source_HOST'],
      target_HOST = packet['target_HOST'],
    )
  
  def send_udp(self, server, port):
    time = str(datetime.datetime.utcnow())
    
    for combo, count in self.combo_count.iteritems():
      combo_record = combo._asdict()
      combo_record['count'] = count
      combo_record['length'] = self.combo_length_sum[combo]
      
      for k,v in self.combo_host[combo].iteritems():
        combo_record[k] = v
      
      combo_record['time'] = time
      
      # print(str(combo_record))
      
      self.UPD_sock.sendto(json.dumps(combo_record), (server, port))
  
  
def main_buffer():
  global line_count, threads
  
  
  line_count = 0
  all_packets = []
  update_time_marker = lambda: datetime.datetime.now() + datetime.timedelta(seconds=SEC_INTERVAL)
  
  time_marker = update_time_marker()
  aggregate = Packet_Aggregate()
  
  UPD_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP

  print("Running packet capture live with Aggregate...")

  for line in sys.stdin:
    line_count += 1
    packet = parse_packet(line)
    if not packet:
      continue
    
    aggregate.ingest(packet)
    
    if datetime.datetime.now() > time_marker:
      aggregate.send_udp(UDP_IP, UDP_PORT)
      aggregate = Packet_Aggregate()
      time_marker = update_time_marker()
    
  
try:
  global line_count
  line_count = 0
  main_buffer()
  
except KeyboardInterrupt:
    print("Exiting...")
except:
  print(get_exception_message())

print('read ' + str(line_count) + ' lines')
