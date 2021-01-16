# -*- coding: utf-8 -*-
import hashlib
import OpenSSL
import multiprocessing
from multiprocessing import Process, Manager
import time
import os
import requests
import json
import sys
import warnings
import random, string

warnings.filterwarnings("ignore", category=FutureWarning)

hash_functions = {
	'md5': hashlib.md5,
	'sha1': hashlib.sha1,
	'sha224': hashlib.sha224,
	'sha256': hashlib.sha256,
	'sha384': hashlib.sha384,
	'sha512': hashlib.sha512
}

HASH_TYPE = 'sha256'
sys.tracebacklimit = 0
node = "node1.stlx.online"

def randomword(length):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(length))

def exit():
	try:
		sys.exit(0)
	except SystemExit:
		os._exit(0)

def hash_func(*args) -> bytes:
	t = b''.join(str(arg).encode('utf-8') for arg in args)
	return hash_functions[HASH_TYPE](t).digest()


def expand(buf, cnt, space_cost) -> int:
	for s in range(1, space_cost):
		buf.append(hash_func(cnt, buf[s - 1]))
		cnt += 1
	return cnt


def mix(buf, cnt, delta, salt, space_cost, time_cost):
	for t in range(time_cost):
		for s in range(space_cost):
			buf[s] = hash_func(cnt, buf[s - 1], buf[s])
			cnt += 1
			for i in range(delta):
				other = int(hash_func(cnt, salt, t, s, i).hex(), 16) % space_cost
				cnt += 1
				buf[s] = hash_func(cnt, buf[s], buf[other])
				cnt += 1

def extract(buf) -> bytes:
	return buf[-1]


def balloon(password, salt, space_cost, time_cost, delta=3) -> bytes:
	buf = [hash_func(0, password, salt)]
	cnt = 1
	cnt = expand(buf, cnt, space_cost)
	mix(buf, cnt, delta, salt, space_cost, time_cost)
	return extract(buf)


def balloon_hash(password, salt):
	delta = 6
	time_cost = 12
	space_cost = 24
	return balloon(password, salt, space_cost, time_cost, delta=delta).hex()

def get_result(hashv):
    positions = [1, 2, 3, 5, 7, 11, 13, 17]
    val = 0;
    n=1;
    maxd = 0;
    for pos in positions:
        val = val + (int(hashv[pos], 16)*(16**n))
        n = n + 1
        maxd = maxd + (15*(16**n))

    diff = int(maxd/val)
    return int(diff/30)

def worker(num, address, node, dictmgr, diff, miningid, s):
	dictmgr[1] = 0
	dictmgr[2] = 0
	dmgr3 = [0, "", ""]
	dmgr3[0] = 0
	dmgr3[1] = ""
	dmgr3[2] = ""
	dictmgr[3] = dmgr3
	dmgr4 = [0, "", ""]
	response = ""
	run = 1
	errors = 0
	decimals = 100000000
	
	while(run):
		try:
			nresponse = s.get('https://' + str(node) + '/api/?q=getminingtemplate&id=' + str(miningid))
			data = nresponse.json()
			dictmgr[1] = data
			if response != dictmgr[1]:
				response = dictmgr[1]
				if num == 0:
					print("[Worker] New block: " + str(dictmgr[1]['result']['height']) + ", Pending balance: " + str(balance['balance']/decimals) + " STLX")
			time.sleep(30)
			errors = 0
			try:
				dmgr4 = dictmgr[3]
				nresponse = s.get('https://' + str(node) + '/api/?q=submitshare&address=' + str(address) + '&diff=' + str(dmgr4[0]) + '&nonce=' + str(dmgr4[1]) + '&hash=' + str(dmgr4[2]))
				print('https://' + str(node) + '/api/?q=submitshare&address=' + str(address) + '&diff=' + str(dmgr4[0]) + '&nonce=' + str(dmgr4[1]) + '&hash=' + str(dmgr4[2]))
				print('[Worker] Share sent with diff: ' + str(dmgr4[0]) + ', hash: ' + str(dmgr4[2]))
				dictmgr[3] = dmgr3
				dictmgr[2] = dictmgr[2] + 1
			except Exception as e:
				print(e)
		except Exception as e:
			errors = errors + 1
			if errors % 8 == 0:
				print("Connection error. Retrying...")
		except KeyboardInterrupt:
			run = 0
			print('Interrupted')


def mining(num, address, privkey, pubkey, miningid, cores, dictmgr, diff):
	printed = 0
	n = 0
	it = int(time.time())
	response = ""
	run = 1
	errors = 0
	dmgr3 = [0, "", ""]
	
	while(run):
		try:
			if (int(time.time()) % 30 == num and int(time.time()) != printed):
				printed = int(time.time())
				print("[Hashing] " + "Thread " + str(num) + ": " + str(round(n/(int(time.time()+1)-it),2)) + " h/s, Shares: " + str(dictmgr[2]))
			a = randomword(16)
			res = balloon_hash(address + "-" + str(dictmgr[1]['result']['height']) + "-" + str(dictmgr[1]['result']['difficulty']) + "-" + str(dictmgr[1]['result']['prevhash']), a)
			dmgr3 = dictmgr[3]
			if get_result(res) > dmgr3[0]:
				dmgr3[0] = get_result(res)
				dmgr3[1] = a
				dmgr3[2] = res
				dictmgr[3] = dmgr3
			n = n+1
			errors = 0
		except Exception as e:
			print(str(e))
			errors = errors + 1
		except KeyboardInterrupt:
			run = 0
			print('Interrupted')

def startmining(address, cores):
	ismining = 0
	miningid = randomword(12)
	s = requests.Session()
	cores = int(cores)
	manager = Manager() 
	dictmgr = manager.dict()
	threads = [None] * cores
	for i in range(cores):
		if i == 0:
			params = [i, address, node, dictmgr, 0, miningid, s]
			threads[i] = Process(target=worker, args=(params))
		else:
			params = [i, address, "", "", miningid, cores, dictmgr, 0]
			threads[i] = Process(target=mining, args=(params))
		threads[i].start()
		if i == 0:
			print("[Hashing] Started networker thread")
		else:
			print("[Hashing] Started thread" + str(i))
		time.sleep(1)
	ismining = 1
	while(1):
		time.sleep(45)
		print("[Hashing] Continuing hashing...")

if __name__ == '__main__':
	multiprocessing.freeze_support()
	try:
		cores = 0
		while int(cores) < 1:
			cores = input("\n\nSelect number of threads:  ")
			if int(cores) > 0:
				args = len(sys.argv)
				startmining(sys.argv[args-1], int(cores)+1)
			else:
				print("Invalid number of threads")
				print(" ")
	except Exception as e:
		print(e)
		print("Interrupted")
	except KeyboardInterrupt:
		print('Interrupted')
		try:
			sys.exit(0)
		except SystemExit:
			os._exit(0)
