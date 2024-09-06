gobuster vhost -u example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 4 --append-domain



gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains=top1million-5000.txt -t 10 
