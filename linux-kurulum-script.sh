#!/bin/bash
clear
echo ""
echo "1) Auto Port Kapatma"
echo "2) İptables tek ip bağlantı limiti"
echo "3) İptables rst paketi limitleme"
echo "4) İptables ssh brute force engelleme"
echo "5) İptables Block packets with bogus TCP flags"
echo "6) İptables Spoof saldýrý paketini engeller"
echo "7) İptables nmap port taraması kapatma"
echo "8) Sunucu güncellemelerini yapar ve temel şeyleri kurar"
echo "9) Java 8,11,16 sürümlerini kurar"
echo "10) Mariadb 10.3 Kurulumu"
echo "11) Gizli"
echo "---------------------------"
echo "Bir seçenek seçiniz örnk (1): "
read numara
case $numara in
1)	read -p "--> Lütfen IP Adresinizi giriniz.: " sayi
	read -p "--> Kapatılacak Başlangıç Port (BungeeCord Port Numaranızı Girmeyin): " port
	read -p "--> Kapatılacak Bitiş Port (BungeeCord Port Numaranızı Girmeyin): " port2
	iptables -I INPUT ! -s $sayi -p tcp --dport $port:$port2 -j DROP
	sudo iptables-save
	sudo service iptables save
  iptables-save > /etc/iptables/rules.v4
	echo ""
	echo ""
	echo -e "\033[36mBelirlediğiniz BungeeCord ipiniz "$sayi" belirlediğiniz "$port"-"$port2" ayarlanmıştır..\033[0m"
	echo -e "\033[36mBelirlediğiniz başlangıç port "$port"-"$port2" bitiş port dışarıdan gelen TCP bağlantılarına kapatılmıştır..\033[0m"
	echo -e "\033[91mZergi\033[0m"
	echo ""
	echo ""
;;
2)
read -p "--> Tek ip bağlantı limiti ne olsun: " tekip
/sbin/iptables -A INPUT -p tcp -m connlimit --connlimit-above $tekip -j REJECT --reject-with tcp-reset
	sudo iptables-save
	sudo service iptables save
  iptables-save > /etc/iptables/rules.v4
	echo ""
	echo ""
	echo -e "Kurallar başarıyla girildi."
	echo ""
	echo ""
;;
3)
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT 
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
	sudo iptables-save
	sudo service iptables save
  iptables-save > /etc/iptables/rules.v4
	echo ""
	echo ""
	echo -e "Kurallar başarıyla girildi."
	echo ""
	echo ""
;;
4)
/sbin/iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
/sbin/iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP  
/sbin/iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set 
/sbin/iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
	sudo iptables-save
	sudo service iptables save
  iptables-save > /etc/iptables/rules.v4
	echo ""
	echo ""
	echo -e "Kurallar başarıyla girildi."
	echo ""
	echo ""
;;
5)
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
	sudo iptables-save
	sudo service iptables save
  iptables-save > /etc/iptables/rules.v4
	echo ""
	echo ""
	echo -e "Kurallar başarıyla girildi."
	echo ""
	echo ""
;;
6)
/sbin/iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP 
/sbin/iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
	sudo iptables-save
	sudo service iptables save
  iptables-save > /etc/iptables/rules.v4
	echo ""
	echo ""
	echo -e "Kurallar başarıyla girildi."
	echo ""
	echo ""
;;
7)
/sbin/iptables -N port-scanning 
/sbin/iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
/sbin/iptables -A port-scanning -j DROP
	sudo iptables-save
	sudo service iptables save
  iptables-save > /etc/iptables/rules.v4
	echo ""
	echo ""
	echo -e "Kurallar başarıyla girildi."
	echo ""
	echo ""
;;
8)
sudo apt update -y
sudo apt upgrade -y
sudo apt install screen -y
sudo apt install htop -y
sudo apt install nload -y
sudo apt install nano -y
sudo apt install iptables-persistent -y
sudo systemctl enable iptables
sudo systemctl start iptables
	echo ""
	echo ""
	echo -e "Kurulum tamamlandı."
	echo ""
	echo ""
;;
9)
sudo apt-get install -y apt-transport-https ca-certificates wget dirmngr gnupg software-properties-common
sudo wget -qO - https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public | sudo apt-key add -
sudo add-apt-repository --yes https://adoptopenjdk.jfrog.io/adoptopenjdk/deb/
sudo apt update -y
apt install adoptopenjdk-8-hotspot -y
apt install adoptopenjdk-11-hotspot -y
apt install adoptopenjdk-16-hotspot -y
echo "Varsayılan Java sürümünü seç!"
echo "---------------------------"
update-alternatives --config java
	echo ""
	echo ""
	echo -e "Kurulum tamamlandı."
	echo ""
	echo ""
;;
10)
sudo apt update -y
sudo apt install -y mariadb-server mariadb-client
sudo systemctl enable mariadb
sudo systemctl start mariadb
sudo mysql_secure_installation
	echo ""
	echo ""
	echo -e "Kurulum tamamlandı."
	echo ""
	echo ""
;;
11)
apt-get -y update
apt-get -y upgrade
apt-get -y dist-upgrade
sudo apt-get install -y apt-transport-https ca-certificates wget dirmngr gnupg software-properties-common
sudo wget -qO - https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public | sudo apt-key add -
sudo add-apt-repository --yes https://adoptopenjdk.jfrog.io/adoptopenjdk/deb/
sudo apt update -y
apt install adoptopenjdk-8-hotspot -y
apt install adoptopenjdk-11-hotspot -y
apt install adoptopenjdk-16-hotspot -y
echo "Varsayılan Java sürümünü seç!"
echo "---------------------------"
update-alternatives --config java
	echo ""
	echo ""
	echo -e "Kurulum tamamlandı."
	echo ""
	echo ""
;;
*)
echo "--> Hatalı bir seçenek seçtiniz."
esac
