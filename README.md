# purrfect-cipher-scanner
This script is too check on weak ciphers

## Features
This scanner will do the nmap scan.

<b>Command:</b> `nmap --script ssl-enum-ciphers -p <port> <IP>`

If the scanner doesnt found any "ciphers", then it will try to telnet. 

<b>Telnet</b>
- $${\color{green}Port \space open}$$
- $${\color{red}Port \space closed}$$

If `Port closed` it will try to ping. Check either the host is reachable or not.


|No|Features|
|--|--------|
|1|This scanner will do the nmap scan.<br>

<b>Command:</b> `nmap --script ssl-enum-ciphers -p <port> <IP>`<br>

If the scanner doesnt found any "ciphers", then it will try to telnet. <br>

<b>Telnet</b>
- $${\color{green}Port \space open}$$
- $${\color{red}Port \space closed}$$

If `Port closed` it will try to ping. Check either the host is reachable or not.

## Result
<img width="350" alt="Screenshot 2024-08-29 at 12 19 21 PM" src="https://github.com/user-attachments/assets/eed6b0cf-c972-42a0-8fe2-1e3a25c8bab5">
