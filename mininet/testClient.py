#test Client

import httplib
import sys
import time

http_server = sys.argv[1]
client_no = sys.argv[2]
number_of_tests = 20
log_name='log_{0}.txt'.format(client_no)
log = open(log_name,'a')

for x in range(number_of_tests):
	
#	cmd = raw_input('input command (ex. GET index.html')
#	cmd = cmd.split()
#	if cmd[0] == 'exit':
#		break

	cmd = ['GET','blah.html']
	conn = httplib.HTTPConnection(http_server)
	startTime = time.time()
	conn.request(cmd[0],cmd[1])
	rsp = conn.getresponse()
	stopTime = time.time()
	conn.close()

	data_received = rsp.read()
	print 'nr({0}/{4}) {1} {2} {3}'.format(x,rsp.status,rsp.reason,data_received,number_of_tests)
	log.write('{0}. time:{1} status:{2} reason:{3}\n'.format(x,stopTime-startTime,rsp.status,rsp.reason))
log.close()

