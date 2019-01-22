#!/bin/bash
passwd -l root

sed -i '20s/.*/session required pam_lastlog.so showfailed/' /etc/pam.d/system-auth

sed -i '$ a auth [default=die] pam_faillock.so authfail deny=3 
unlock_time=604800 fail_interval=900' /etc/pam.d/system-auth

sed -i '$ a auth required pam_faillock.so authsucc deny=3 unlock_time=604800 fail_interval=900' /etc/pam.d/system-auth

sed -i '16s/$/ remember=24/' /etc/pam.d/system-auth

echo "install usb-storage /bin/false" > /etc/modprobe.d/usb-storage.conf

authconfig --passalgo=sha512 --update


sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS\ 15/g' /etc/login.defs 

sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS\ 8/g' /etc/login.defs 

sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE\ 7/g' /etc/login.defs 


echo -e 'session required pam_lastlog.so showfailed' >> /etc/pam.d/system-auth

echo -e 'auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900' >> /etc/pam.d/system-auth

echo -e 'auth required pam_faillock.so authsucc deny=3 unlock_time=604800 fail_interval=900' >> /etc/pam.d/system-auth

echo -e 'auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900' >> /etc/pam.d/password-auth

echo -e 'auth required pam_faillock.so authsucc deny=3 unlock_time=604800 fail_interval=900' >> /etc/pam.d/password-auth

sed -i 's/use_authtok/use_authtok remember=24/' >> /etc/pam.d/system-auth

echo -e 'SINGLE=/sbin/sulogin' >> /etc/sysconfig/init

echo -e 'NETWORKING_IPV6=no' >> /etc/sysconfig/network 

echo -e 'IPV6INIT=no' >> /etc/sysconfig/network

echo "tty1" > /etc/securetty

chmod 700 /root

wget https://klaver.it/linux/sysctl.conf; cat sysctl.conf > /etc/sysctl.conf

rm -rf sysctl.conf

yum install epel-release -y 
yum install --enablerepo="epel" ufw -y 
ufw enable 
iptables -P INPUT DROP 
iptables -I INPUT -i lo -j ACCEPT 
iptables -P INPUT DROP 
iptables -P FORWARD DROP 
iptables -P OUTPUT ACCEPT 
iptables -A INPUT -m state --state NEW,ESTABLISHED -j ACCEPT 
iptables -A INPUT -i eth0 -s 192.168.0.0/24 -j DROP 
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP 
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j LOG --log-prefix "IP_SPOOF A: " 
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP 
iptables -A INPUT -i eth1 -s 192.168.0.0/24 -j DROP 
iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j DROP 
iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j LOG --log-prefix "IP_SPOOF A: " 
iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j DROP 
iptables -A INPUT -i eth1 -s 10.0.0.0/8 -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix "IP_SPOOF A: " 
iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j DROP 
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix "IP_SPOOF A: "
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP 
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP 
iptables -A INPUT -i eth1 -p icmp --icmp-type echo-request -j DROP 
iptables -A INPUT -i eth0 -p icmp --icmp-type echo-request -j DROP 
iptables -A INPUT -s 1.2.3.4 -p tcp --destination-port 80 -j LOG --log-level crit 
iptables -N syn-flood 
iptables -A syn-flood -m limit --limit 100/second --limit-burst 150 -j RETURN 
iptables -A syn-flood -j LOG --log-prefix "SYN flood: " 
iptables -A syn-flood -j DROP 
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP 
iptables -A INPUT -f -j DROP 
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP 
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP 
iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP 
iptables -A OUTPUT -p icmp --icmp-type 8 -j DROP

echo -e 'LABEL=/boot /boot ext2 defaults,ro 1 2' >> /etc/fstab

echo -e 'tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0' >> /etc/fstab

echo "ALL:ALL" >> /etc/hosts.deny 
echo "sshd:ALL" >> /etc/hosts.allow 
echo -e 'blacklist usb_storage' >> /etc/modprobe.d/dccp-blacklist.conf 
echo -e 'modprobe -r usb_storage' >> /etc/rc.local 
echo -e 'exit 0' >> /etc/rc.local 
echo -e 'hard core 0' >> /etc/security/limits.conf 

chown root:root /etc/anacrontab 
chmod og-rwx /etc/anacrontab 
chown root:root /etc/crontab 
chmod og-rwx /etc/crontab 
chown root:root /etc/cron.hourly 
chmod og-rwx /etc/cron.hourly 
chown root:root /etc/cron.daily 
chmod og-rwx /etc/cron.daily 
chown root:root /etc/cron.weekly 
chmod og-rwx /etc/cron.weekly 
chown root:root /etc/cron.monthly 
chmod og-rwx /etc/cron.monthly 
chown root:root /etc/cron.d 
chmod og-rwx /etc/cron.d 
chmod 644 /etc/passwd 
chown root:root /etc/passwd 
chmod 644 /etc/group 
chown root:root /etc/group 
chmod 600 /etc/shadow 
chown root:root /etc/shadow 
chmod 600 /etc/gshadow 
chown root:root /etc/gshadow 
chown root:root /etc/fstab 


yum -y install rsyslog 
systemctl enable rsyslog.service 
systemctl start rsyslog.service 

systemctl enable auditd.service 
systemctl start auditd.service 

echo -e "-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules" >> /etc/audit/audit.rules 

echo -e "-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules" >> /etc/audit/audit.rules 

echo -e "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime" >> /etc/audit/audit.rules 
echo -e "-k audit_time_rules" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules" >> /etc/audit/audit.rules

echo -e "-w /etc/localtime -p wa -k audit_time_rules" >> /etc/audit/audit.rules

echo -e "-w /etc/group -p wa -k audit_account_changes" >> /etc/audit/audit.rules 
echo -e "-w /etc/passwd -p wa -k audit_account_changes" >> /etc/audit/audit.rules 
echo -e "-w /etc/gshadow -p wa -k audit_account_changes" >> /etc/audit/audit.rules 
echo -e "-w /etc/shadow -p wa -k audit_account_changes" >> /etc/audit/audit.rules 
echo -e "-w /etc/security/opasswd -p wa -k audit_account_changes" >> /etc/audit/audit.rules 

echo -e "-a always,exit -F arch=ARCH -S sethostname -S setdomainname -k audit_network_modifications" >> /etc/audit/audit.rules 
echo -e "-w /etc/issue -p wa -k audit_network_modifications" >> /etc/audit/audit.rules 
echo -e "-w /etc/issue.net -p wa -k audit_network_modifications" >> /etc/audit/audit.rules 
echo -e "-w /etc/hosts -p wa -k audit_network_modifications" >> /etc/audit/audit.rules 
echo -e "-w /etc/sysconfig/network -p wa -k audit_network_modifications" >> /etc/audit/audit.rules

echo -e "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules

echo -e "-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S chmod  -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules


echo -e "-a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules


echo -e "-a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules


echo -e "-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules


echo -e "-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules


echo -e "-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules


echo -e "-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules


echo -e "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules 
echo -e "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules

echo -e "-w /var/run/utmp -p wa -k session" >> /etc/audit/audit.rules 
echo -e "-w /var/log/btmp -p wa -k session" >> /etc/audit/audit.rules 
echo -e "-w /var/log/wtmp -p wa -k session" >> /etc/audit/audit.rules 


echo -e "-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules


echo -e "-a always,exit -F arch=ARCH -S mount -F auid>=500 -F auid!=4294967295 -k export" >> /etc/audit/audit.rules

echo -e "-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules

echo -e "-w /etc/sudoers -p wa -k actions" >> /etc/audit/audit.rules

echo -e "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules 
echo -e "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules 
echo -e "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules 
echo -e "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules 


echo -e "-e 2" >> /etc/audit/audit.rules


yum -y update
 

