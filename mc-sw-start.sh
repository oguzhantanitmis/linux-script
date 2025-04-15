#!/bin/bash
cd /opt/mc-server/proxy

JAVA="java"
JAR=$(ls spigot*.jar | head -n 1)
RAM="1G"
FLAGS="-Duser.language=tr -Dfile.encoding=UTF-8 -XX:+UseG1GC -XX:G1HeapRegionSize=4M -XX:+UnlockExperimentalVMOptions -XX:+ParallelRefProcEnabled -XX:+AlwaysPreTouch -XX:MaxInlineLevel=15"

# Eğer "proxy" screen oturumu yoksa sunucuyu başlat.
if ! screen -list | grep -q "\.proxy"; then
    echo "Sunucu başlatılıyor..."
    screen -dmS proxy ${JAVA} -Xmx${RAM} -Xms512M ${FLAGS} -jar ${JAR}
fi

# Screen oturumu çalışırken bekle.
while screen -list | grep -q "\.proxy"; do
    sleep 5
done

echo "Proxy screen oturumu kapandı."
exit 1
