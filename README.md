Motivation:
After deploying a large network of Cisco router and switches it can be difficult to test if SSH or Telnet works on the device or not
when connecting from the management server for a given username password and enable password.

Objective:

After network deployment checking for:
1) Is the device reachable from management station.
2) Are we able to connect to the device via telnet.
3) Are we able to connect to the device via SSH.
4) Does a particluar set of credentials work for logging into the device


Logic of script:

1) The script first does a ping to all the IP to check which all IPs are reachable.
2) The script then connects to all the reachable IP via telnet to check we are able to connect.( using telnetlib)
3) The script then connects to all the reachable IP via SSH to check if we are able to connect.
-default username is :""
-default password is :""
if we get an authentication exception it means that we were able to connect.
4) The script then tries username and password used to connect the device via SSH if SSH was found enabled for the device in step 3.
5) If SSH was not enabled for the device but telnet was, it tries to connect via telnet using the cerdentials shared.
6) The script then tries to use the username and password to connect to get into the privilege mode using the enable password.

Input to the script :
management subnet.
excluded IP from the subnet.
any addiontional IPs you want to include.

username - username.yaml
password - password.yaml
enablepassword - enablepassword.yaml


Output of script:
output.csv


PS:

The Script can also be used in cases where you want to check out of a combination of cerdentials something can be used to login into the device.

