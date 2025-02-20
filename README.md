# Firewall Internet Failover

Python script running on my RaspberryPi firewall that monitors two paths to the Internet (a primary and a secondary) and manages routing failover between them based on network reachability.

Each path is used to ping an endpoint to check for connectivity; on failure a verification ping destination is used to ensure the failure isn't due to the test endpoint having failed.

The script prefers the primary path and will failover to the secondary if it becomes unavailable, and will fail back to the primary when connectivity is restored.

The script will create a device in Home Assistant via MQTT with the name and status of the interfaces.

Note: the script will also enable proxy arp on the two interfaces, but that's specific to my setup and may not be neceesary depending on network design.

Installation


- Put the failover.py script into /usrt/local/bin and make it executable chmod 0755 /usr/local/bin/failover.py
- Copy the other files into /usr/local/etc 
- Edit /usr/local/etc/failover.env to set the correct MQTT broker, username and password
- Set the file permissions to protect the password chown root /usr/local/etc/failover.env && chmod 600 /usr/local/etc/failover.env
- Edit /usr/local/etc/failover.yml to your liking, specifically the interface names and next hop IP addresses for routers on the end of he Internet connections
- Add the service cd /etc/systemd/system; ln -s /usr/local/etc/failover.service
- Enable and start the service systemctl enable failover && systemctl start failover

If you use PPP / PPPOE on your firewall, changes will be required to the route add and remove commands.

