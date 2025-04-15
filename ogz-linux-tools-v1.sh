#!/bin/bash
# OGZ-Linux tools v1.sh - Detaylı Loglama ve Renkli Çıktı
# Tüm komut çıktıları $HOME/hmc_script.log dosyasına yazılacaktır.

# Renk Değişkenleri (ANSI escape)
RED="\e[1;31m"
GREEN="\e[1;32m"
YELLOW="\e[1;33m"
BLUE="\e[1;34m"
CYAN="\e[1;36m"
RESET="\e[0m"

LOGFILE="$HOME/ogz_script.log"

# Tüm çıktıları hem ekrana hem log dosyasına yönlendiriyoruz.
exec > >(tee -a "$LOGFILE") 2>&1

# sudo ön teyidi (kullanıcının şifresi sorulur)
sudo -v

# Fonksiyon: Loglama (tarih ve renkli)
log() {
    echo -e "$(date +'%F %T') - $*"
}

# Fonksiyon: Hata kontrolü (son komut çıkış kodunu kontrol eder)
check_error() {
    if [ $? -ne 0 ]; then
        log "${RED}HATA: $1 (Çıkış kodu: $?)${RESET}"
    else
        log "${GREEN}Başarılı: $1${RESET}"
    fi
}

# Fonksiyon: İptables Yedekle
backup_iptables() {
    log "${BLUE}Mevcut iptables kuralları yedekleniyor...${RESET}"
    sudo iptables-save > "$HOME/iptables_backup_$(date +'%F_%T').rules"
    check_error "İptables yedeği alınamadı."
}

########################################################################
# Fonksiyon: 1) Auto Port Kapatma Gelişmiş
auto_port_block() {
    log "${CYAN}Auto Port Kapatma seçildi...${RESET}"
    
    chainName=""
    while [[ -z "$chainName" ]]; do
        read -p "Oluşturmak istediğiniz özel zincirin ismi (örn: customGroup1): " chainName
        if [[ -z "$chainName" ]]; then
            echo -e "${RED}Hata: Zincir ismi boş bırakılamaz, lütfen geçerli bir isim giriniz.${RESET}"
        fi
    done

    allowedPorts=()
    while true; do
        read -p "Açık tutulmasını istediğiniz portu giriniz (sadece rakam, örn: 8080): " port
        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}Hata: Port numarası yalnızca rakamlardan oluşmalıdır. Lütfen tekrar deneyin.${RESET}"
            continue
        fi
        allowedPorts+=("$port")
        
        # Burada 2'ye veya ENTER'a basılırsa ekleme bitiyor
        read -p "Başka port eklemek istiyor musunuz? (1: evet, 2 veya ENTER: hayır): " morePorts
        if [[ "$morePorts" != "1" ]]; then
            break
        fi
    done

    # SSH bağlantısı için 22 portunun durumu
    read -p "SSH bağlantınızın kopmaması için 22 portu açık bırakılacak. Eğer kapatılmasını istiyorsanız 'hayır' yazın, açık kalmasını istiyorsanız boş bırakın: " sshchoice
    sshchoice=$(echo "$sshchoice" | tr '[:upper:]' '[:lower:]')
    if [[ "$sshchoice" == "hayir" || "$sshchoice" == "hayır" ]]; then
        new_allowed=()
        for p in "${allowedPorts[@]}"; do
            [[ "$p" == "22" ]] && continue
            new_allowed+=("$p")
        done
        allowedPorts=("${new_allowed[@]}")
        log "Kullanıcının isteğiyle 22 portu listeden çıkarıldı."
    else
        found=0
        for p in "${allowedPorts[@]}"; do
            if [[ "$p" == "22" ]]; then
                found=1
                break
            fi
        done
        if [[ $found -eq 0 ]]; then
            allowedPorts+=("22")
            log "SSH bağlantınızı korumak için 22 portu otomatik olarak eklendi."
        fi
    fi

    log "Girdiğiniz portlar: ${allowedPorts[*]}"

    backup_iptables

    sudo iptables -N "$chainName" 2>/dev/null
    sudo iptables -F "$chainName"
    sudo iptables -D INPUT -p tcp -j "$chainName" 2>/dev/null

    portsList=$(IFS=,; echo "${allowedPorts[*]}")
    sudo iptables -A "$chainName" -p tcp -m multiport --dports "$portsList" -j ACCEPT
    check_error "ACCEPT kuralı"
    sudo iptables -A "$chainName" -p tcp -j DROP
    check_error "DROP kuralı"

    # INPUT zincirinin sonuna ekliyoruz, önceki kuralların önüne geçmesin.
    sudo iptables -A INPUT -p tcp -j "$chainName"
    check_error "Özel zincirin INPUT'a eklenmesi"

    log "Kurallar uygulandı. Açık tutulacak portlar: ${allowedPorts[*]}."
    echo -e "${YELLOW}Diğer tüm TCP portları kapatıldı. (Önceden oluşturulmuş diğer zincirlere dokunulmadı.)${RESET}"

    read -p "Kurallar kalıcı olarak kaydedilsin mi? (1: evet, 2: hayır): " saveChoice
    if [[ "$saveChoice" == "1" ]]; then
        sudo sh -c 'iptables-save > /etc/iptables/rules.v4'
        log "IPTables kuralları /etc/iptables/rules.v4 dosyasına kaydedildi."
    else
        log "Kalıcı kaydetme atlandı."
    fi
}

backup_iptables() {
    log "${BLUE}Mevcut iptables kuralları yedekleniyor...${RESET}"
    sudo iptables-save > "$HOME/iptables_backup_$(date +'%F_%T').rules"
    # Mesajı nötr hale getiriyoruz
    check_error "iptables yedeği alma"
}

########################################################################
# Fonksiyon: 2) İptables Tek IP Bağlantı Limiti
iptables_single_ip_limit() {
    read -p "--> Tek IP bağlantı limiti ne olsun (Sorunlar açabilir!): " tekip
    sudo iptables -A INPUT -p tcp -m connlimit --connlimit-above "$tekip" -j REJECT --reject-with tcp-reset
    check_error "Tek IP bağlantı limiti kurulamadı."
    sudo iptables-save > /etc/iptables/rules.v4
    log "Tek IP bağlantı limiti kuralları uygulandı."
}

########################################################################
# Fonksiyon: 3) İptables RST Paket Limitleme
iptables_rst_limit() {
    sudo iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT 
    sudo iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
    sudo iptables-save > /etc/iptables/rules.v4
    log "RST paket limitleme kuralları uygulandı."
}

########################################################################
# Fonksiyon: 4) İptables SSH Brute Force Engelleme
iptables_ssh_bruteforce() {
    local chain="ssh-brute"
    log "SSH brute force engelleme işlemi başlatılıyor... (Chain: $chain)"
    sudo iptables -N "$chain" 2>/dev/null
    sudo iptables -F "$chain"
    sudo iptables -D INPUT -p tcp --dport 22 -j "$chain" 2>/dev/null
    sudo iptables -I INPUT -p tcp --dport 22 -j "$chain"
    sudo iptables -A "$chain" -m conntrack --ctstate NEW -m recent --set
    sudo iptables -A "$chain" -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
    sudo iptables-save > /etc/iptables/rules.v4
    log "SSH brute force engelleme kuralları (Chain: $chain) uygulandı."
}

########################################################################
# Fonksiyon: 5) İptables: Block Packets with Bogus TCP Flags
iptables_bogus_flags() {
    local chain="bogus-tcp"
    log "Bogus TCP flag engelleme işlemi başlatılıyor... (Chain: $chain)"
    sudo iptables -t mangle -N "$chain" 2>/dev/null
    sudo iptables -t mangle -F "$chain"
    sudo iptables -t mangle -I PREROUTING -j "$chain"
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags FIN,ACK FIN -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags ACK,URG URG -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags ACK,FIN FIN -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags ACK,PSH PSH -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags ALL ALL -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags ALL NONE -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 
    sudo iptables -t mangle -A "$chain" -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
    sudo iptables-save > /etc/iptables/rules.v4
    log "Bogus TCP flag kuralları (Chain: $chain) uygulandı."
}

########################################################################
# Fonksiyon: 6) İptables: Spoof Saldırı Paketini Engelleme
iptables_spoof_block() {
    local chain="spoof-block"
    log "Spoof saldırı paketlerini engelleme işlemi başlatılıyor... (Chain: $chain)"
    sudo iptables -t mangle -N "$chain" 2>/dev/null
    sudo iptables -t mangle -F "$chain"
    sudo iptables -t mangle -I PREROUTING -j "$chain"
    sudo iptables -t mangle -A "$chain" -s 224.0.0.0/3 -j DROP 
    sudo iptables -t mangle -A "$chain" -s 169.254.0.0/16 -j DROP 
    sudo iptables -t mangle -A "$chain" -s 172.16.0.0/12 -j DROP 
    sudo iptables -t mangle -A "$chain" -s 192.0.2.0/24 -j DROP 
    sudo iptables -t mangle -A "$chain" -s 192.168.0.0/16 -j DROP 
    sudo iptables -t mangle -A "$chain" -s 10.0.0.0/8 -j DROP 
    sudo iptables -t mangle -A "$chain" -s 0.0.0.0/8 -j DROP 
    sudo iptables -t mangle -A "$chain" -s 240.0.0.0/5 -j DROP 
    sudo iptables -t mangle -A "$chain" -s 127.0.0.0/8 ! -i lo -j DROP
    sudo iptables-save > /etc/iptables/rules.v4
    log "Spoof saldırı paketleri engelleme kuralları (Chain: $chain) uygulandı."
}

########################################################################
iptables_nmap_block() {
    local chain="nmap-scan"
    log "Nmap port taraması engelleme işlemi başlatılıyor... (Chain: $chain)"
    
    # Mangle tablosunda zinciri oluşturup temizle
    sudo iptables -t mangle -N "$chain" 2>/dev/null
    sudo iptables -t mangle -F "$chain"
    
    # PREROUTING zincirine yalnızca belirli RST paketlerini yönlendiren bir kural ekliyoruz.
    # Böylece tüm trafik değil, yalnızca --tcp-flags SYN,ACK,FIN,RST RST eşleşen TCP paketleri zincire yönlendirilir.
    sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j "$chain"
    
    # Zincir içinde, limit dahilinde RST paketlerine RETURN, limit aşımında DROP uyguluyoruz.
    sudo iptables -t mangle -A "$chain" -m limit --limit 1/s --limit-burst 2 -j RETURN
    sudo iptables -t mangle -A "$chain" -j DROP
    
    sudo iptables-save > /etc/iptables/rules.v4
    log "Nmap port taraması engelleme kuralları (Chain: $chain) uygulandı."
}


########################################################################
# Fonksiyon: 8) Sunucu Güncellemeleri ve Temel Kurulum
basic_setup() {
    log "${BLUE}Temel sistem güncellemeleri ve kurulum işlemleri başlatılıyor...${RESET}"

    sudo apt update -y
    check_error "Paket listesi güncellemesi (apt update)"
    
    sudo apt install -y screen htop nload nano iptables-persistent
    check_error "Gerekli paketlerin kurulumu (screen, htop, nload, nano, iptables-persistent)"
    
    sudo systemctl enable iptables
    check_error "iptables servisinin enable edilmesi"
    
    sudo systemctl start iptables
    check_error "iptables servisinin başlatılması"

    log "${GREEN}Temel kurulum işlemleri tamamlandı.${RESET}"
}


########################################################################
# Fonksiyon: 9) Java Sürümleri Kurulumu
install_java() {
    log "${BLUE}Java sürümleri kurulumu başlatılıyor...${RESET}"
    
    # Gerekli paketlerin kurulması
    sudo apt-get install -y apt-transport-https ca-certificates wget dirmngr gnupg software-properties-common
    check_error "Gerekli paketler kurulması"
    
    # Adoptium (Temurin) repolarını ekliyoruz:
    log "${BLUE}Adoptium GPG anahtarı ekleniyor...${RESET}"
    wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public | sudo apt-key add -
    check_error "Adoptium GPG anahtarı eklenmesi"
    
    # Dağıtımınızın kod adını otomatik olarak alıyoruz:
    CODENAME=$(lsb_release -sc)
    log "${BLUE}Dağıtım kod adı: ${CODENAME}${RESET}"
    
    log "${BLUE}Adoptium deposu ekleniyor...${RESET}"
    echo "deb https://packages.adoptium.net/artifactory/deb/ ${CODENAME} main" | sudo tee /etc/apt/sources.list.d/adoptium.list
    check_error "Adoptium deposu eklenemedi"

    sudo apt update -y
    check_error "Paket listesi güncellemesi"
    
    # Temurin JDK paketlerini kuruyoruz
    sudo apt-get install -y temurin-24-jdk temurin-22-jdk temurin-21-jdk temurin-17-jdk
    check_error "Temurin JDK paketleri kurulması"
    
    log "${GREEN}Java sürümleri yüklendi. Varsayılan sürümü seçmek için aşağıdaki komutu kullanın:${RESET}"
    sudo update-alternatives --config java
}


########################################################################
# Fonksiyon: 10) Mariadb 10.5 Kurulumu
install_mariadb() {
    log "${BLUE}Mariadb kurulumu başlatılıyor...${RESET}"
    
    sudo apt update -y
    check_error "Paket listesi güncellemesi"
    
    sudo apt install -y mariadb-server
    check_error "Mariadb kurulumu"
    
    sudo systemctl enable mariadb
    check_error "Mariadb servisini enable etme"
    
    sudo systemctl start mariadb
    check_error "Mariadb servisini başlatma"
    
    # mysql_secure_installation interaktif bir araçtır.
    # Otomatikleştirmek için expect script ya da ön ayarlamalar eklenebilir.
    sudo mysql_secure_installation
    check_error "mysql_secure_installation çalıştırma"
    
    log "${GREEN}Mariadb kurulumu tamamlandı.${RESET}"
}


########################################################################
# Fonksiyon: 11) Güncellemeleri Yap
update_system() {
    log "${BLUE}Sistem güncellemeleri başlatılıyor...${RESET}"
    
    sudo apt-get update -y
    check_error "Paket listesi güncellemesi"
    
    sudo apt-get upgrade -y
    check_error "Sistem yükseltmesi (upgrade)"
    
    sudo apt-get dist-upgrade -y
    check_error "Dist-upgrade işlemi"
    
    sudo apt-get autoremove -y
    check_error "Gereksiz paketlerin kaldırılması (autoremove)"
    
    sudo apt-get autoclean -y
    check_error "Paket önbelleğinin temizlenmesi (autoclean)"
    
    log "${GREEN}Sistem güncellemeleri tamamlandı.${RESET}"
}

########################################################################
# Fonksiyon: 12) Güvenli Minecraft Kullanıcısı Oluşturma
create_minecraft_user() {
    log "${CYAN}Minecraft için özel kullanıcı oluşturuluyor...${RESET}"
    read -p "Kullanıcı adı (örn: minecraft): " mcuser
    if [[ -z "$mcuser" ]]; then
        log "${RED}Kullanıcı adı boş bırakılamaz. Fonksiyon sonlandırılıyor.${RESET}"
        return 1
    fi
    if id "$mcuser" &>/dev/null; then
        log "${RED}Kullanıcı '$mcuser' zaten mevcut. İşleme devam edilmeyecek.${RESET}"
        return 1
    fi
    read -p "Sunucu klasörü (varsayılan: /opt/$mcuser): " mcdir
    mcdir=${mcdir:-/opt/$mcuser}
    sudo useradd -m -d "$mcdir" -s /bin/bash "$mcuser"
    check_error "Minecraft kullanıcısı oluşturulamadı."
    sudo chown -R "$mcuser:$mcuser" "$mcdir"
    check_error "Dizin sahipliği değiştirilemedi."
    sudo chmod -R 750 "$mcdir"
    check_error "Dizin izinleri ayarlanamadı."
    log "${GREEN}Minecraft kullanıcısı oluşturuldu: $mcuser, klasör: $mcdir${RESET}"
}

########################################################################
# Fonksiyon: 13) Minecraft Systemd Servisi Oluşturma (Screen üzerinden)
create_minecraft_service() {
    log "${CYAN}Minecraft Systemd Servisi oluşturuluyor (screen üzerinden)...${RESET}"
    read -p "Servis adı (örn: skyblock): " srvname
    if [[ -z "$srvname" ]]; then
        log "${RED}Servis adı boş bırakılamaz.${RESET}"
        return 1
    fi
    default_dir="/opt/$srvname"
    read -p "Sunucunun bulunduğu yer tam yol (örn: $default_dir): " srvdir
    srvdir=${srvdir:-$default_dir}
    # Sistem kullanıcılarını listelemek için getent ve awk kullanıyoruz (UID >= 1000 ve shell '/bin/bash')
    mapfile -t users < <(getent passwd | awk -F: '$3>=1000 && $7 ~ /bash/ {print $1}')
    if [ ${#users[@]} -eq 0 ]; then
        log "${RED}Sistem kullanıcıları bulunamadı!${RESET}"
        return 1
    fi
    log "Mevcut kullanıcılar:"
    for i in "${!users[@]}"; do
        echo "$((i+1))) ${users[i]}"
    done
    read -p "Çalıştırılacak kullanıcıyı seçiniz (sayı ile): " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -le 0 ] || [ "$choice" -gt "${#users[@]}" ]; then
        log "${RED}Geçersiz seçim.${RESET}"
        return 1
    fi
    mcuser="${users[$((choice - 1))]}"
    log "Seçilen kullanıcı: ${GREEN}$mcuser${RESET}"

    sudo tee /etc/systemd/system/${srvname}.service > /dev/null <<EOF
[Unit]
Description=HavanaMC ${srvname} Sunucusu (screen üzerinden)
After=network.target

[Service]
User=${mcuser}
WorkingDirectory=${srvdir}
ExecStart=${srvdir}/start.sh
ExecStop=/usr/bin/screen -S ${srvname} -X quit
Restart=on-failure
RestartSec=3
SuccessExitStatus=0 143
LimitNOFILE=65535

# Güvenlik ayarları
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=${srvdir}

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reexec
    sudo systemctl daemon-reload
    log "${GREEN}${srvname} systemd servisi oluşturuldu. Başlatmak için: sudo systemctl start ${srvname}${RESET}"
}

########################################################################
# Fonksiyon: 14) IPTables Zinciri Oluştur, Port Kapatır, IP'ye İzin Verir
iptables_port_block() {
    log "${CYAN}IPTables port kapatma işlemi başlatılıyor...${RESET}"
    
    # Zincir ismi için boş geçilemez, geçerli bir değer alana kadar tekrarla
    chainName=""
    while [[ -z "$chainName" ]]; do
        read -p "İptables zinciri ismi ne olsun? (örn: mcserver): " chainName
        if [[ -z "$chainName" ]]; then
            echo -e "${RED}Hata: Zincir ismi boş bırakılamaz, lütfen geçerli bir isim giriniz.${RESET}"
        fi
    done

    # Kapatılacak port bilgisini al; boş geçilemez ve yalnızca rakamlardan oluşmalıdır.
    port=""
    while true; do
        read -p "Kapatılacak port (örn: 3306): " port
        if [[ -z "$port" ]]; then
            echo -e "${RED}Hata: Port bilgisi boş bırakılamaz, lütfen geçerli bir port giriniz.${RESET}"
            continue
        fi
        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}Hata: Port numarası yalnızca rakamlardan oluşmalıdır. Lütfen tekrar deneyin.${RESET}"
            continue
        fi
        break
    done

    read -p "İzin verilecek IP adresi var mı? (1: evet, 2: hayır): " allowChoice

    allowedIPs=()
    if [[ "$allowChoice" == "1" ]]; then
        while true; do
            read -p "IP adresi girin: " ip
            allowedIPs+=("$ip")
            read -p "Eklemek istediğiniz başka IP adresi var mı? (1: evet, 2: hayır): " more
            if [[ "$more" != "1" ]]; then
                break
            fi
        done
    fi

    backup_iptables

    sudo iptables -N "$chainName" 2>/dev/null
    sudo iptables -F "$chainName"
    sudo iptables -D INPUT -p tcp --dport "$port" -j "$chainName" 2>/dev/null
    sudo iptables -I INPUT -p tcp --dport "$port" -j "$chainName"

    if [[ ${#allowedIPs[@]} -gt 0 ]]; then
        for ip in "${allowedIPs[@]}"; do
            sudo iptables -A "$chainName" -s "$ip" -j RETURN
        done
    fi

    sudo iptables -A "$chainName" -j DROP

    log "${GREEN}IPTables kuralları uygulandı: INPUT zincirinde port $port için \"$chainName\" zinciri eklendi.${RESET}"
    if [[ ${#allowedIPs[@]} -gt 0 ]]; then
        log "İzin verilen IP adresleri: ${allowedIPs[*]}"
    else
        log "Hiçbir IP adresine izin verilmedi; port $port tamamen kapatıldı."
    fi

    read -p "Kurallar kalıcı olarak kaydedilsin mi? (1: evet, 2: hayır): " saveChoice
    if [[ "$saveChoice" == "1" ]]; then
        sudo sh -c 'iptables-save > /etc/iptables/rules.v4'
        log "${GREEN}IPTables kuralları /etc/iptables/rules.v4 dosyasına kaydedildi.${RESET}"
    else
        log "${YELLOW}Kalıcı kaydetme atlandı.${RESET}"
    fi
}

##############################################
# Fonksiyon: TCP Optimizasyonu (Kalıcılık için /etc/sysctl.d/99-ogz-tcp.conf)
tcp_optimization() {
    log "${BLUE}TCP optimizasyon ayarları kalıcı olarak uygulanıyor...${RESET}"
    
    # Ayarları /etc/sysctl.d/99-ogz-tcp.conf dosyasına ekliyoruz.
    sudo tee /etc/sysctl.d/99-ogz-tcp.conf > /dev/null <<EOF
net.core.somaxconn=1024
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.ip_local_port_range=1024 65535
EOF
    check_error "TCP optimizasyon ayarlarının dosyaya yazılması"
    
    # Tüm sysctl ayarlarını yeniden yükleyip uyguluyoruz.
    sudo sysctl --system
    check_error "TCP optimizasyon ayarlarının uygulanması"
    
    log "${GREEN}TCP optimizasyon ayarları kalıcı hale getirildi.${RESET}"
}

##############################################
# Fonksiyon: Swap Ayarı (vm.swappiness) Kalıcı Yapma (/etc/sysctl.d/99-ogz-swap.conf)
set_swap() {
    read -p "Swap değeri (swappiness) kaç olsun? (önerilen: 10, boş bırakılırsa 10 kabul edilir): " swap_val
    swap_val=${swap_val:-10}
    if ! [[ "$swap_val" =~ ^[0-9]+$ ]]; then
       echo -e "${RED}Hata: Lütfen sadece sayı giriniz.${RESET}"
       return 1
    fi
    log "${BLUE}vm.swappiness değeri ${swap_val} olarak kalıcı hale getiriliyor...${RESET}"
    
    # Ayarı /etc/sysctl.d/99-ogz-swap.conf dosyasına yazıyoruz.
    echo "vm.swappiness=${swap_val}" | sudo tee /etc/sysctl.d/99-ogz-swap.conf > /dev/null
    check_error "vm.swappiness ayarının dosyaya yazılması"
    
    # Yeni ayarları uygulatıyoruz.
    sudo sysctl --system
    check_error "vm.swappiness ayarının uygulanması"
    
    log "${GREEN}vm.swappiness değeri ${swap_val} olarak kalıcı hale getirildi.${RESET}"
}

##############################################
# Fonksiyon: Ulimit Ayarlarını Kalıcı Yapma (/etc/security/limits.conf)
set_ulimit() {
    response=""
    while true; do
         read -p "Önerilen ulimit ayarlarını uygulamak istiyor musunuz? (evet/hayır): " response
         if [[ -z "$response" ]]; then
              echo -e "${YELLOW}Lütfen 'evet' veya 'hayır' yazınız.${RESET}"
              continue
         fi
         response=$(echo "$response" | tr '[:upper:]' '[:lower:]')
         if [[ "$response" == "evet" || "$response" == "hayır" ]]; then
              break
         else
              echo -e "${YELLOW}Lütfen 'evet' veya 'hayır' giriniz.${RESET}"
         fi
    done

    if [[ "$response" == "evet" ]]; then
         # /etc/security/limits.conf dosyasını yedekliyoruz
         sudo cp /etc/security/limits.conf /etc/security/limits.conf.bak.$(date +'%F_%T')
         log "${BLUE}Eski limits.conf dosyası yedeklendi.${RESET}"
         
         # Önerilen ayarları ekliyoruz; zaten varsa eşleşmeyen yeni satır eklenir.
         # Eğer eklenmiş satırların güncellenmesi gerekiyorsa, sed komutları kullanılabilir.
         sudo bash -c "echo '* soft nofile 10000' >> /etc/security/limits.conf"
         sudo bash -c "echo '* hard nofile 30000' >> /etc/security/limits.conf"
         check_error "Ulimit ayarlarının /etc/security/limits.conf'ye eklenmesi"
         log "${GREEN}Ulimit ayarları /etc/security/limits.conf dosyasına eklendi. (Değişikliklerin geçerli olması için oturum kapatılıp açılmalıdır.)${RESET}"
    else
         log "${YELLOW}Ulimit ayarları uygulanmayacak.${RESET}"
    fi
}

########################################################################
# Ana Menü
while true; do
    clear
    echo -e "${BLUE}──────────────────────────────────────────────${RESET}"
    echo -e "${GREEN}          OGZ-Linux tools v1.sh               ${RESET}"
    echo -e "${BLUE}──────────────────────────────────────────────${RESET}"
    echo ""
    echo -e "${YELLOW}1) Auto Port Kapatma Gelişmiş${RESET}"
    echo -e "${YELLOW}2) İptables Tek IP Bağlantı Limiti${RESET}"
    echo -e "${YELLOW}3) İptables RST Paketi Limitleme${RESET}"
    echo -e "${YELLOW}4) İptables SSH Brute Force Engelleme${RESET}"
    echo -e "${YELLOW}5) İptables: Block Packets with Bogus TCP Flags${RESET}"
    echo -e "${YELLOW}6) İptables: Spoof Saldırı Paketini Engelleme${RESET}"
    echo -e "${YELLOW}7) İptables: Nmap Port Taraması Kapatma${RESET}"
    echo -e "${YELLOW}8) Sunucu Güncellemeleri ve Temel Kurulum${RESET}"
    echo -e "${YELLOW}9) Java Sürümleri Kurulumu${RESET}"
    echo -e "${YELLOW}10) Mariadb 10.5 Kurulumu${RESET}"
    echo -e "${YELLOW}11) Güncellemeleri Yap${RESET}"
    echo -e "${YELLOW}12) Güvenli Minecraft Kullanıcısı Oluştur${RESET}"
    echo -e "${YELLOW}13) Minecraft Systemd Servisi Oluştur (Screen üzerinden)${RESET}"
    echo -e "${YELLOW}14) IPTables Zinciri Oluştur, Port Kapatır, IP'ye İzin Verir${RESET}"
    echo -e "${YELLOW}15) TCP Optimizasyonu Uygula${RESET}"
    echo -e "${YELLOW}16) Swap Ayarı (vm.swappiness) Uygula${RESET}"
    echo -e "${YELLOW}17) SYSTEMCTL ICINDE VAR! Ulimit Ayarı Uygula (kalıcı)${RESET}"
    
    echo -e "${BLUE}──────────────────────────────────────────────${RESET}"
    echo ""
    read -p "Bir seçenek seçiniz (örn: 1): " numara

    case "$numara" in
        1) auto_port_block ;;
        2) iptables_single_ip_limit ;;
        3) iptables_rst_limit ;;
        4) iptables_ssh_bruteforce ;;
        5) iptables_bogus_flags ;;
        6) iptables_spoof_block ;;
        7) iptables_nmap_block ;;
        8) basic_setup ;;
        9) install_java ;;
        10) install_mariadb ;;
        11) update_system ;;
        12) create_minecraft_user ;;
        13) create_minecraft_service ;;
        14) iptables_port_block ;;
        15) tcp_optimization ;;
        16) set_swap ;;
        17) set_ulimit ;;
        *) echo -e "${RED}--> Hatalı bir seçenek seçtiniz.${RESET}" ;;
    esac

    echo ""
    read -p "Devam etmek için Enter'a basınız..." pause
done
