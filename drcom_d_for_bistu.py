#coding=UTF-8
#Licensed under the AGPLv3
#此版本适配北京信息科技大学

import socket, struct, time,random,re
from hashlib import md5

#userinfo
username=''  #学号
password=''  #密码
host_ip = ''  #dhcp到的ip地址
mac = 0x0050bace070c
#userinfo_end

#ues_rconfig
AUTO_RE_LOGIN = True  #是否在断线后自动重新登陆，默认为真
#ues_rconfig_end

#config #请不要在不了解的情况下随意修改以下参数
server = '192.168.211.3'
CONTROLCHECKSTATUS = '\x20'
ADAPTERNUM = '\x02'
IPDOG = '\x01'
host_name = 'DRCOM'
PRIMARY_DNS = '211.82.96.1'
dhcp_server = '211.68.32.204'
AUTH_VERSION = '\x0a\x00'
host_os = 'WINDIAOS'
KEEP_ALIVE_VERSION = '\xdb\x02'
#config_end

UNLIMITED_RETRY = True
EXCEPTION = False

class ChallengeException (Exception):
	def __init__(self):
		pass

class LoginException (Exception):
	def __init__(self):
		pass

def version():
	print "============================" 
	print "DrCOM Login Client for BISTU"
	print "============================" 

def md5sum(s):
    m = md5()
    m.update(s)
    return m.digest()


def keep_alive1(salt,tail,pwd,svr):
	foo = struct.pack('!H',int(time.time())%0xFFFF)
	data = '\xff' + md5sum('\x03\x01'+salt+pwd) + '\x00\x00\x00'
	data += tail
	data += foo + '\x00\x00\x00\x00'
	print '[keep_alive1] send'#data.encode('hex'))
	s.sendto(data, (svr, 61440))
	while True:
		data, address = s.recvfrom(1024)
		if data[0] == '\x07':
			break
		else:
			print '[keep-alive1]recv/not expected'#data.encode('hex')
	#print('[keep-alive1] recv',data.encode('hex'))


def keep_alive_package_builder(number,random,tail,type=1,first=False):
	data = '\x07'+ chr(number) + '\x28\x00\x0b' + chr(type)
	data += KEEP_ALIVE_VERSION+'\x2f\x12' + '\x00' * 6
	data += tail
	data += '\x00' * 4
	#data += struct.pack("!H",0xdc02)
	if type == 3:
		foo = ''.join([chr(int(i)) for i in host_ip.split('.')]) # host_ip
		#use double keep in main to keep online .Ice
		crc = '\x00' * 4
		#data += struct.pack("!I",crc) + foo + '\x00' * 8
		data += crc + foo + '\x00' * 8
	else: #packet type = 1
		data += '\x00' * 16
	return data


def dump(n):
	s = '%x' % n
	if len(s) & 1:
		s = '0' + s
	return s.decode('hex')


def keep_alive2(*args):
	tail = ''
	packet = ''
	svr = server
	ran = random.randint(0,0xFFFF)
	ran += random.randint(1,10)
	packet = keep_alive_package_builder(0,dump(ran),'\x00'*4,1,True)
	#packet = keep_alive_package_builder(0,dump(ran),dump(ran)+'\x22\x06',1,True)
	print '[keep_alive2] send1'#packet.encode('hex')
	while True:
		s.sendto(packet, (svr, 61440))
		data, address = s.recvfrom(1024)
		if data.startswith('\x07'):
			break
		else:
			continue
			#print '[keep_alive2] recv/unexpected',data.encode('hex')
	#print '[keep_alive2] recv1',data.encode('hex')
	
	ran += random.randint(1,10)   
	packet = keep_alive_package_builder(1,dump(ran),'\x00'*4,1,False)
	#print '[keep_alive2] send2',packet.encode('hex')
	s.sendto(packet, (svr, 61440))
	while True:
		data, address = s.recvfrom(1024)
		if data[0] == '\x07':
			break
	#print '[keep_alive2] recv2',data.encode('hex')
	tail = data[16:20]


	ran += random.randint(1,10)   
	packet = keep_alive_package_builder(2,dump(ran),tail,3,False)
	#print '[keep_alive2] send3',packet.encode('hex')
	s.sendto(packet, (svr, 61440))
	while True:
		data, address = s.recvfrom(1024)
		if data[0] == '\x07':
			break
	#print '[keep_alive2] recv3',data.encode('hex')
	tail = data[16:20]
	print "[keep-alive] keep-alive loop was in daemon."
	i = 3

	while True:
		try:
			keep_alive1(SALT,package_tail,password,server)
			print '[keep_alive2] send'
			ran += random.randint(1,10)   
			packet = keep_alive_package_builder(i,dump(ran),tail,1,False)
			#print('DEBUG: keep_alive2,packet 4\n',packet.encode('hex'))
			#print '[keep_alive2] send',str(i),packet.encode('hex')
			s.sendto(packet, (svr, 61440))
			data, address = s.recvfrom(1024)
			#print '[keep_alive2] recv',data.encode('hex')
			tail = data[16:20]
			#print('DEBUG: keep_alive2,packet 4 return\n',data.encode('hex'))

			ran += random.randint(1,10)   
			packet = keep_alive_package_builder(i+1,dump(ran),tail,3,False)
			#print('DEBUG: keep_alive2,packet 5\n',packet.encode('hex'))
			s.sendto(packet, (svr, 61440))
			#print('[keep_alive2] send',str(i+1),packet.encode('hex'))
			data, address = s.recvfrom(1024)
			#print('[keep_alive2] recv',data.encode('hex'))
			tail = data[16:20]
			#print('DEBUG: keep_alive2,packet 5 return\n',data.encode('hex'))
			i = (i+2) % 0xFF
			time.sleep(20)
		except:
			print("")
			return


def checksum(s):
	ret = 1234
	for i in re.findall('....', s):
		ret ^= int(i[::-1].encode('hex'), 16)
	ret = (1968 * ret) & 0xffffffff
	return struct.pack('<I', ret)


def mkpkt(salt, usr, pwd, mac):
	data = '\x03\x01\x00'+chr(len(usr)+20)
	data += md5sum('\x03\x01'+salt+pwd)
	data += usr.ljust(36, '\x00')
	data += '\x20' #fixed unknow 1
	data += '\x02' #unknow 2
	data += dump(int(data[4:10].encode('hex'),16)^mac).rjust(6,'\x00') #mac xor md51
	data += md5sum("\x01" + pwd + salt + '\x00'*4) #md52
	data += '\x01' #NIC count
	data += hexip #your ip address1 
	data += '\00'*4 #your ipaddress 2
	data += '\00'*4 #your ipaddress 3
	data += '\00'*4 #your ipaddress 4
	data += md5sum(data + '\x14\x00\x07\x0b')[:8] #md53
	data += '\x01' #ipdog
	data += '\x00'*4 #delimeter
	data += host_name.ljust(32, '\x00')
	data += '\x72\x72\x72\x72' #primary dns: 114.114.114.114
	data += '\x0a\xff\x00\xc5' #DHCP server
	data += '\x08\x08\x08\x08' #secondary dns:8.8.8.8
	data += '\x00' * 8 #delimeter
	data += '\x94\x00\x00\x00' # unknow
	data += '\x05\x00\x00\x00' #os major
	data += '\x01\x00\x00\x00' # os minor
	data += '\x28\x0a\x00\x00' # OS build
	data += '\x02\x00\x00\x00' #os unknown
	data += host_os.ljust(32,'\x00')
	data += '\x00' * 96
	data += AUTH_VERSION
	data += '\x02\x0c'
	data += checksum(data+'\x01\x26\x07\x11\x00\x00'+dump(mac))
	data += '\x00\x00' #delimeter
	data += dump(mac)
	data += '\x00' # auto logout / default: False
	data += '\x00' # broadcast mode / default : False
	data += '\xe8\x90' #unknown
	return data


def challenge(svr,ran):
	while True:
		t = struct.pack("<H", int(ran)%(0xFFFF))
		s.sendto("\x01\x02"+t+"\x09"+"\x00"*15, (svr, 61440))
		try:
			data, address = s.recvfrom(1024)
			#print('[challenge] recv',data.encode('hex'))
		except:
			print('[challenge] Timeout, retrying...')
			continue
		
		if address == (svr, 61440):
			break
		else:
			continue
	#print('[DEBUG] challenge:\n' + data.encode('hex'))
	if data[0] != '\x02':
		raise ChallengeException
	print('[challenge] Challenge packet sent.')
	return data[4:8]


def login(usr, pwd, svr):
	global SALT
	i = 0
	salt = challenge(svr,time.time()+random.randint(0xF,0xFF))
	SALT = salt
	packet = mkpkt(salt, usr, pwd, mac)
	#print('[login] send',packet.encode('hex'))
	s.sendto(packet, (svr, 61440))
	data, address = s.recvfrom(1024)
	#print('[login] recv',data.encode('hex'))
	print('[login] Packet sent.')
	if address == (svr, 61440):
		if data[0] == '\x04':
			print('[login] Login Success')
			return data[23:39]
		else:
			print("[login] Login failed.")
			raise LoginException
			return
	else:
		if i >= 5 and UNLIMITED_RETRY == False :
			print('[login] exception occured.')
			sys.exit(1)
		else:
			print("[login] Login failed.")
			raise LoginException
			return

		
def main():
	global server,username,password,host_name,host_os,dhcp_server,mac,hexip,host_ip,package_tail
	hexip = socket.inet_aton(host_ip)
	host_name = "est-pc"
	host_os = "DrcomGoAway"  #default is 8089D
	dhcp_server = "0.0.0.0"
	count = 0
	while True:
		count = count+1
		print("[main] Prepare the %d times login." % count)
		try:
			package_tail = login(username, password, server)
		except LoginException:
			print("[main] Please check the login information!")
			return
		print("[main] Prepare send heartbeat packet.")
		keep_alive2(SALT,package_tail,password,server)
		print("[main] Dropped.")
		if not AUTO_RE_LOGIN:
			return
		print("Wait 3 seconds...")
		time.sleep(3)
		print("Re-login.")


def try_socket():
#sometimes cannot get the port
	global s,salt
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind(("0.0.0.0", 61440))
		s.settimeout(3)
	except:
		print "...wait 3 seconds"
		time.sleep(3)
		return
	else:
		SALT= ''


if __name__ == "__main__":
	try_socket()
	version()
	main()


