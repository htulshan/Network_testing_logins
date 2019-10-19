import ipaddress
import subprocess
from itertools import repeat
from concurrent.futures import ThreadPoolExecutor
import netmiko
import telnetlib
import time
import re
import csv
import yaml

class Login():

	#to get the ips to run the script on, retruns a list of ips.
	def extract_ip_list(self):
		#userinput
		subnetstr = input("Please enter the subnet of Lab IP: ")

		excludedips = []
		print("Input the excluded IPs, enter 'OK' once done:")
		while True:
			exip = input()
			if exip == 'OK':
				break
			else:
				excludedips.append(exip)

		includedips = []
		print("Input the included IPs, enter 'OK' once done:")
		while True:
			iip = input()
			if iip == 'OK':
				break
			else:
				includedips.append(iip)


		subnetobj = ipaddress.ip_network(subnetstr)
		allhostobj = list(subnetobj.hosts())
		iphost = list(map(str, allhostobj))

		for iip in includedips:
			iphost.append(iip)

		for exip in excludedips:
			if exip in iphost:iphost.remove(exip)

		return iphost

	#to check if the ip passed to it is reachable or not, returns to code along with the ip
	def check_for_reachable_ips(self, ip):
		result = subprocess.run(f'ping -n 3 -w 1 {ip}', stdout=subprocess.DEVNULL)
		return result.returncode, ip

	#to check if SSH is enabled on the device or not by logging into it with default username and password : ''
	def test_if_ssh_is_enabled(self, ip, device_type):

		devicedata = {
			'device_type' : device_type,
			'ip' : ip,
			'username' : '',
			'password' : ''
			}
		try:
			netmiko.ConnectHandler(**devicedata)
		except netmiko.ssh_exception.NetMikoAuthenticationException:
			return True, devicedata['ip'] # if we get a authentication failure, we are able to login connect to the switch using ssh
		except:
			return False, devicedata['ip']#any other exception is taken as failure to connect to the device using SSH
		else:
			return True, devicedata['ip']#if we are able to login into the device using default username and password.

	#to check if telnet is enabled on the device or not by logging into it using telnet.
	def test_if_telnet_is_enabled(self, ip):

		try:
			telnetlib.Telnet(ip)
		except:
			return False, ip#if there is an exception, telnet is not enabled.
		else:
			return True, ip


	#to check if a particular ip can we logged into using the usernames and passwords for SSH enaled clients
	def ssh_login(self, ip, usernamelist, passwordlist, device_type):

		#to try mutliple passwords with a single username simultaneously to speed up the processing.
		for username in usernamelist:

			with ThreadPoolExecutor(max_workers=5) as executor: #tries 5 passwords at a time for the username
				result = list(executor.map(self.ssh_login_per_username, repeat(ip), repeat(username), passwordlist, repeat(device_type)))



			for i in result:
				if i[0]:
					return i[0], i[1], i[2], i[3]
		#returns the first match username/password for which the login was successful, if no match was found retruns False, ip, 'na', 'na
		return False, ip, 'na', 'na'

	#logs into the device using a username and password and returns the result
	def ssh_login_per_username(self, ip, username, password, device_type):

		device = {}
		devicedata = {
			'device_type' : device_type,
			'ip' : ip,
			'username' : username,
			'password' : password
			}

		try:
			device = netmiko.ConnectHandler(**devicedata)
		except:
			return False, ip, username, password
		else:
			device.disconnect()
			return True, ip, username, password

	#to check if a particular ip can we logged into using the usernames and passwords for SSH disabled clients with telnet enabled
	def telnet_login(self, ip, usernamelist, passwordlist):
		logindetailslist = []

		#to try mutliple passwords with a single username simultaneously to speed up the processing.
		for username in usernamelist:
			result = []

			with ThreadPoolExecutor(max_workers=5) as executor: #tries 5 passwords at a time for the username
				result = list(executor.map(self.telnet_login_per_username, repeat(ip), repeat(username), passwordlist))


			for i in result:
				if i[0]:
					return i[0], i[1], i[2], i[3]

		return False, ip, 'na', 'na'


	#logs into the device using a username and password and returns the result
	def telnet_login_per_username(self, ip, username, password):

		device = telnetlib.Telnet(ip)
		time.sleep(2)
		response = device.read_very_eager().decode('ascii')
		if 'Username:' in response :
			device.write(f'{username}\n'.encode('ascii'))
		elif 'Password:' in response :
			device.write(f'{password}\n'.encode('ascii'))
			time.sleep(2)
			response = device.read_very_eager().decode('ascii')
			if '#' in response:
				return True, ip, '', password
			elif '>' in response:
				return True, ip, '', password
			else:
				return False, ip, '', password
		time.sleep(2)

		response = device.read_very_eager().decode('ascii')
		if 'Password:' in response :
			device.write(f'{password}\n'.encode('ascii'))
			time.sleep(2)
			response = device.read_very_eager().decode('ascii')

		if '#' in response:
			return True, ip, username, password
		elif '>' in response:
			return True, ip, username, password
		else:
			return False, ip, username, password

	#to check if we are able to login into the device using the username and password to privilege 15 or not, if not we need to try enable password.
	def enable_device_login(self, devicedata):

		priv = False

		device = netmiko.ConnectHandler(**devicedata)
		response = device.send_command('show privilege')
		privreg = '(?P<priv>\d+)'
		match = re.search(privreg, response)
		if match.group('priv') == '15': #to check what is the privilege level logged into using the username and password
			priv = True
		return priv, devicedata

	#to try an enable password to check if it works
	def try_enable_password(self, devicedata, secret):

		devicedata['secret'] = secret
		devicedata['timeout'] = 2

		try:
			device = netmiko.ConnectHandler(**devicedata)
			device.enable()
		except:
			return False, devicedata
		else:
			return True, devicedata

	#to try multiple enable password for one IP simultaneously to speed up processing
	def enable_login_user(self, devicedata, enablepasswordlist):
		result = []
		with ThreadPoolExecutor(max_workers = 10) as executor:#tries 10 enable passwords in on go.
			result = list(executor.map(self.try_enable_password, repeat(devicedata), enablepasswordlist))

		for i in result:
			if i[0]:
				del i[1]['timeout']
				return i[1]

		devicedata['secret'] = 'Not Found'
		del devicedata['timeout']
		return devicedata

	#to try enable password on multiple IP at the same time to speed up processing.
	def enable_login(self, enablelogindatalist, enablepasswordlist):
		#checks if the default priv is 15
		checkprivdevices = []
		privnot15list = []
		priv15 = []

		with ThreadPoolExecutor(max_workers = 10) as executor:#to check if privilege level is 15 or not #tries 10 IP simultaneously
			checkprivdevices = list(executor.map(self.enable_device_login, enablelogindatalist))

		for i in checkprivdevices:
			if i[0]:
				i[1]['secret'] = 'Not Required'
				priv15.append(i[1])
			else:
				privnot15list.append(i[1])

		result = []
		with ThreadPoolExecutor(max_workers = 10) as executor:#to try enable password on 10 users simultaneously if priv level is not 15
			result = list(executor.map(self.enable_login_user, privnot15list, repeat(enablepasswordlist)))

		return priv15 + result

	#to compile data from output file
	def compiling_data_for_output_file(self, validhostips, reachableips, sshenabledips, telnetenabledips, enableloginresult):
		writedata = []

		for i in validhostips:
			devicedata  = {}
			devicedata['ip'] = i
			devicedata['Reachable'] = ('Yes' if i in reachableips else 'No')
			if devicedata['Reachable'] == 'Yes':
				devicedata['SSH Enabled'] = ('Yes' if i in sshenabledips else 'No')
				devicedata['Telnet Enabled'] = ('Yes' if i in telnetenabledips else 'No')
				if devicedata['SSH Enabled'] == 'Yes' or devicedata['Telnet Enabled'] == 'Yes':
					matchfound = False
					for i in enableloginresult:
						if i['ip'] == devicedata['ip']:
							matchfound = True
							devicedata['username'] = ('Not Required' if i['username'] == '' else i['username'])
							devicedata['password'] = ('Not Required' if i['password'] == '' else i['password'])
							devicedata['secret'] = i['secret']
							devicedata['device_type'] = i['device_type']
							break
					if matchfound:
						pass
					else:
						devicedata['username'] = 'Not Found'
						devicedata['password'] = 'Not Found'
						devicedata['secret'] = 'NA'
						devicedata['device_type'] = 'NA'
				else:
					devicedata['username'] = 'NA'
					devicedata['password'] = 'NA'
					devicedata['secret'] = 'NA'
					devicedata['device_type'] = 'NA'

			else:
				devicedata['SSH Enabled'] = 'NA'
				devicedata['Telnet Enabled'] = 'NA'
				devicedata['username'] = 'NA'
				devicedata['password'] = 'NA'
				devicedata['secret'] = 'NA'
				devicedata['device_type'] = 'NA'
			writedata.append(devicedata)
		return(writedata)

	def main(self):
		validhostips = [] #list of valid hosts
		reachableips = [] #list of reachale ips
		telnetenabledips = [] #list of telnet enabled ips
		sshenabledips = [] #list of ssh enabled ips
		usernamelist = [] #list of username
		passwordlist = [] #list of password
		telnetminussships = [] #list of IPs that have only telnet working, no ssh
		sshloginresult = [] #result from trying to login into the device via SSH
		telnetloginresult = [] #result from trying to login into the device via telnet


		#taking input from the files
		#reading usernames
		with open('username.yaml') as f:
			usernamelist = yaml.safe_load(f)


		#reading passwords
		with open('password.yaml') as f:
			passwordlist = yaml.safe_load(f)


		#reading enable passwords
		with open('enablepassword.yaml') as f:
			enablepasswordlist = yaml.safe_load(f)


		#to calculate valid ip range
		validhostips = self.extract_ip_list()
		print('=='*20)
		print("Range of useable IPs is:")
		print(validhostips)
		print('=='*20)


		print('=='*20)
		input("To start the script processing press Return to exit type the break sequence :")
		print('=='*20)


		#to check if IP is reachable
		print('=='*20)
		print("Checking for subset of reachable ips.")
		print('=='*20)
		result = []
		with ThreadPoolExecutor(max_workers=10) as executor: # checks for 10 IPs simultaneously
			result = list(executor.map(self.check_for_reachable_ips, validhostips))

		for returncode, ip in result:
			if returncode == 0:
				reachableips.append(ip)

		print('=='*20)
		print("Range of reachable IPs is:")
		print(reachableips)
		print('=='*20)


		#to check if telnet is enabled
		print('=='*20)
		print("Checking for subset of telnet enabled ips.")
		print('=='*20)
		result = []
		with ThreadPoolExecutor(max_workers=10) as executor: #checks for telnet on 10 devices simultaneously
			result = list(executor.map(self.test_if_telnet_is_enabled, reachableips))
		for returncode, ip in result:
			if returncode:
				telnetenabledips.append(ip)

		print('=='*20)
		print("Range of telnet enabled IPs is:")
		print(telnetenabledips)
		print('=='*20)


		#to check if ssh is enabled
		print('=='*20)
		print("Checking for subset of SSH enabled ips.")
		print('=='*20)
		result = []
		with ThreadPoolExecutor(max_workers=10) as executor: #checks for SSH on 10 devices simultaneously
			result = list(executor.map(self.test_if_ssh_is_enabled, reachableips, repeat('cisco_ios')))
		for returncode, ip in result:
			if returncode:
				sshenabledips.append(ip)

		print('=='*20)
		print("Range of SSH enabled IPs is:")
		print(sshenabledips)
		print('=='*20)


		#removing ssh enabled ip from telnet enabled ips
		telnetminussships = telnetenabledips.copy()
		for i in sshenabledips:
			if i in telnetminussships: telnetminussships.remove(i)


		#trying to login into SSH enaled devices.
		print('=='*20)
		print("Trying to login into SSH enabled devices.")
		print('=='*20)
		with ThreadPoolExecutor(max_workers=5) as executor: #tries to login into 5 different device at the same time to speed up the process
			sshloginresult = list(executor.map(self.ssh_login, sshenabledips, repeat(usernamelist), repeat(passwordlist), repeat('cisco_ios')))
		print('=='*20)
		print("IPs and there login details")
		for i in sshloginresult:
			if i[0]:
				print(f'For IP {i[1]} : Username {i[2]} Password {i[3]}')
		print('=='*20)


		#for telnet enabled IPs that have issues with SSH login
		print('=='*20)
		print("Trying to login into telnet enabled devices that have SSH disabled")
		print('=='*20)
		with ThreadPoolExecutor(max_workers=5) as executor:#tries to login into 5 different device at the same time to speed up the process
			telnetloginresult = list(executor.map(self.telnet_login, telnetminussships, repeat(usernamelist), repeat(passwordlist)))
		print('=='*20)
		print("IPs and there login details")
		for i in telnetloginresult:
			if i[0]:
				print(f'For IP {i[1]} : Username {i[2]} Password {i[3]}')
		print('=='*20)


		#compiling data to be given to enable password funtions
		enablelogindatalist = []
		for i in sshloginresult:
			if i[0]:
				enablelogindatalist.append({'device_type' : 'cisco_ios', 'ip' : i[1], 'username' : i[2], 'password' : i[3]})
		for i in telnetloginresult:
			if i[0]:
				enablelogindatalist.append({'device_type' : 'cisco_ios_telnet', 'ip' : i[1], 'username' : i[2], 'password' : i[3]})
		print('=='*20)
		print("Data passed to find enable password:")
		for i in enablelogindatalist:
			print(i)
		print('=='*20)

		#trying to login into the device for different enable passwords
		print('=='*20)
		print("Trying to login into the devices using different enable password")
		print('=='*20)
		enableloginresult = self.enable_login(enablelogindatalist, enablepasswordlist)
		print('=='*20)
		print("Data received after trying enable passwords")
		for i in enableloginresult:
			print(i)
		print('=='*20)


		#compiling data
		writedata = self.compiling_data_for_output_file(validhostips, reachableips, sshenabledips, telnetenabledips, enableloginresult)

		#writing data to csv file
		with open('output.csv', 'w') as f:
			writer = csv.DictWriter(f, fieldnames = list(writedata[0].keys()), quoting=csv.QUOTE_NONNUMERIC)
			writer.writeheader()
			for d in writedata:
				writer.writerow(d)

		print('=='*20)
		print("Data written to file output.csv")
		input("Hit Return to exit the script ")
		print('=='*20)

if __name__ == "__main__":
	test = Login()
	test.main()
