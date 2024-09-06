##Apache server:

1. sudo systemctl start apache2
2. sudo systemctl stop apache2
3. sudo systemctl restart apache2
4. enable systemctl apache2
5. sudo nano /etc/apache2/apache2.conf (apache config file to change port and other things)



##Gobuster subdomain Enumeration:

1. gobuster vhost -u example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 4 --append-domain
2. gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains=top1million-5000.txt -t 10 
