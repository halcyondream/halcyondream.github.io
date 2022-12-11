---
title: Reflections on Tenable's CTF (2022)
date: 2022-06-26
---

Tenable sponsored a CTF this month; I learned about it 12 hours after it started, but was able to assemble a team and compete. My team scored 800 points total; this landed us in 361st place (out of 1357 teams total). Of the 800 points, I scored 500 myself: successfully completing 5 challenges.

Write-ups have already been published, and many of them go very in-depth. Here is a quick overview of some strategies that I used in order to complete the challenges:

- **300 points**. Three challenges were based on basic web security. You can use Burp Suite in order to see the flags, in cleartext, in each response. 
- **100 points**. One forensics challenge required you to "de-obfuscate" a redaction on a PDF document. To complete this challenge, and find the flag, I used **PeePDF** to analyze the PDF stream data and find the flag. (More about this tool later.) Object 24 contains a base64 string. Decode this to reveal a PNG file, which contains the flag.
- **100 points**. Another forensics challenge hid the flag inside a PCAP file. Open this in Wireshark and follow the Modbus stream. The flag is right there, but with strange characters delimiting it. Remove the characters to reveal the flag's string.

Here are some reflections:

- With any kind of application-security challenges, my recommendation is to use the in-built browser that Burp Suite provides. This will consolidate your workspace and free up your favorite browser.
- PeePDF is written for Python2. Peepdf is also no longer available as a Kali package. My recommendation is to install Python2, clone the official PeePDF repo, and use the Python2 runtime to actually use this tool (`python2 peepdf.py`, for example). You can install Python2 separately from your default python. (Side note: Hexdump is not very helpful for analyzing PDFs because PDFS use compression, which changes the decoding, and obfuscates a simple search result.)
- Wireshark and Netminer are great forensics tools for analyzing PCAP files. In this case, Netminer did not provide any results for this challenge, but it is very helpful to enumerate credentials and files. (You can enumerate credentials and files from Wireshark, but it requires more effort.)