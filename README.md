#######################
Задание 1:
Запустить nginx на нестандартном порту 4881 с включенным selinux
Варианты решения:
	1. Посредством утилиты audit2why для лога /var/log/audit/audit.log найти возможный вариант решения:

		[root@selinux ~]# grep 1705244816.509:812 /var/log/audit/audit.log |audit2why
		type=AVC msg=audit(1705244816.509:812): avc:  denied  { name_bind } for  pid=2821 comm="nginx" src=4881 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket permissive=0

	        Was caused by:
        	The boolean nis_enabled was set incorrectly.
        	Description:
        	Allow nis to enabled

	        Allow access by executing:
        	# setsebool -P nis_enabled 1
		[root@selinux ~]#

	   	Разрешаем 4881 порт через "setsebool -P nis_enabled 1"

	2. Разрешаем 4881 для типа http_port_t
	
	[root@selinux ~]# semanage port -l | grep http
	http_cache_port_t              tcp      8080, 8118, 8123, 10001-10010
	http_cache_port_t              udp      3130
	http_port_t                    tcp      80, 81, 443, 488, 8008, 8009, 8443, 9000
	pegasus_http_port_t            tcp      5988
	pegasus_https_port_t           tcp      5989
	[root@selinux ~]# 
	
	semanage port -a -t http_port_t -p tcp 4881

	Как результат:
	
	[root@selinux ~]# semanage port -l | grep http_port_t
	http_port_t                    tcp      4881, 80, 81, 443, 488, 8008, 8009, 8443, 9000
	pegasus_http_port_t            tcp      5988
	[root@selinux ~]#
	
	и сервис nginx стартует успешно.
		
	3. Посредством утилиты audit2allow для лога /var/log/audit/audit.log:
	
	[root@selinux ~]# grep nginx /var/log/audit/audit.log | audit2allow -M nginx
	******************** IMPORTANT ***********************
	To make this policy package active, execute:

	semodule -i nginx.pp

	[root@selinux ~]#	   
	
	После выполнения команды в текущей директории создается файл nginx.pp, применяя который "semodule -i nginx.pp" мы разрешаем 4881 для nginx'a и он успешно стартует.

#######################
Задание 2
Разобраться почему не разрешает обновить зону ДНС

Решение:
	с помощью утилит audit2why было найдено, что присутствует проблема с разрешениями к файлу /etc/named/dynamic/named.ddns.lab.view1.jnl:
	[root@ns01 ~]# cat /var/log/audit/audit.log | audit2why
type=AVC msg=audit(1705248308.694:1867): avc:  denied  { write } for  pid=5093 comm="isc-worker0000" name="named" dev="sda1" ino=5028531 scontext=system_u:system_r:named_t:s0 tcontext=system_u:object_r:named_zone_t:s0 tclass=dir permissive=0

        Was caused by:
                Unknown - would be allowed by active policy
                Possible mismatch between this policy and the one under which the audit message was generated.

                Possible mismatch between current in-memory boolean settings vs. permanent ones.

type=AVC msg=audit(1705248574.676:1892): avc:  denied  { create } for  pid=5093 comm="isc-worker0000" name="named.ddns.lab.view1.jnl" scontext=system_u:system_r:named_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0

        Was caused by:
                Unknown - would be allowed by active policy
                Possible mismatch between this policy and the one under which the audit message was generated.

                Possible mismatch between current in-memory boolean settings vs. permanent ones.

type=AVC msg=audit(1705248689.449:1920): avc:  denied  { write } for  pid=5093 comm="isc-worker0000" path="/etc/named/dynamic/named.ddns.lab.view1.jnl" dev="sda1" ino=67620336 scontext=system_u:system_r:named_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0

        Was caused by:
                Missing type enforcement (TE) allow rule.

                You can use audit2allow to generate a loadable module to allow this access.

	[root@ns01 ~]
	
	Все файлы в /etc/named имеют тип etc_t

	[root@ns01 ~]# ls -laZ /etc/named
	drw-rwx---. root named system_u:object_r:etc_t:s0       .
	drwxr-xr-x. root root  system_u:object_r:etc_t:s0       ..
	drw-rwx---. root named unconfined_u:object_r:etc_t:s0   dynamic
	-rw-rw----. root named system_u:object_r:etc_t:s0       named.50.168.192.rev
	-rw-rw----. root named system_u:object_r:etc_t:s0       named.dns.lab
	-rw-rw----. root named system_u:object_r:etc_t:s0       named.dns.lab.view1
	-rw-rw----. root named system_u:object_r:etc_t:s0       named.newdns.lab
	[root@ns01 ~]#

	Но конфиги named должны располагаться в директории /var/named, вместо /etc/named, тогда у них тип будет named_zone_t
	[root@ns01 ~]# semanage fcontext -l|grep named
	/etc/rndc.*                                        regular file       system_u:object_r:named_conf_t:s0
	/var/named(/.*)?                                   all files          system_u:object_r:named_zone_t:s0

	После диагностики было найдено, что проблема заключается в файлах named.conf и ansible playbook'е.
	Эти файлы были подкорректированы с правильными путями (/var/named) 
	Как результат изменение зоны проходит успешно:
	[vagrant@client ~]$ nsupdate -k /etc/named.zonetransfer.key
	>  server 192.168.50.10
	> zone ddns.lab
	> update add www.ddns.lab. 60 A 192.168.50.15
	> send
	> quit
	[vagrant@client ~]$
	
	[vagrant@client ~]$ dig @192.168.50.10 www.ddns.lab

	; <<>> DiG 9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.15 <<>> @192.168.50.10 www.ddns.lab
	; (1 server found)
	;; global options: +cmd
	;; Got answer:
	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7380
	;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2

	;; OPT PSEUDOSECTION:
	; EDNS: version: 0, flags:; udp: 4096
	;; QUESTION SECTION:
	;www.ddns.lab.                  IN      A

	;; ANSWER SECTION:
	www.ddns.lab.           60      IN      A       192.168.50.15

	;; AUTHORITY SECTION:
	ddns.lab.               3600    IN      NS      ns01.dns.lab.

	;; ADDITIONAL SECTION:
	ns01.dns.lab.           3600    IN      A       192.168.50.10

	;; Query time: 1 msec
	;; SERVER: 192.168.50.10#53(192.168.50.10)
	;; WHEN: Sun Jan 14 16:42:00 UTC 2024
	;; MSG SIZE  rcvd: 96

	[vagrant@client ~]$
