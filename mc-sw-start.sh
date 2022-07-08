#!/bin/bash
clear
echo ""
echo "1) proxy start"
echo "2) Çakma lobi start"
echo "3) Lobi start"
echo "4) Skyblock start"
echo "5) Tekblok start"
echo "---------------------------"
echo "Bir seçenek seçiniz örnk (1): "
read numara
case $numara in
1)
screen -dmS "proxy" bash -c "trap 'echo gotsigint' INT; cd /home/mc-servers/proxy ; ./start.sh;  bash"
	echo ""
	echo ""
	echo -e "Proxy başlatıldı."
	echo ""
	echo ""
;;
2)
screen -dmS "cakmalobi" bash -c "trap 'echo gotsigint' INT; cd /home/mc-servers/cakmalobi ; ./start.sh;  bash"
	echo ""
	echo ""
	echo -e "Çakmalobi başlatıldı."
	echo ""
	echo ""
;;
3)
screen -dmS "lobi" bash -c "trap 'echo gotsigint' INT; cd /home/mc-servers/lobi ; ./start.sh;  bash"
	echo ""
	echo ""
	echo -e "Lobi başlatıldı."
	echo ""
	echo ""
;;
4)
screen -dmS "skyblock" bash -c "trap 'echo gotsigint' INT; cd /home/mc-servers/skyblock ; ./start.sh;  bash"
	echo ""
	echo ""
	echo -e "Skyblock başlatıldı."
	echo ""
	echo ""
;;
5)
screen -dmS "tekblok" bash -c "trap 'echo gotsigint' INT; cd /home/mc-servers/tekblok ; ./start.sh;  bash"
	echo ""
	echo ""
	echo -e "Tekblok başlatıldı."
	echo ""
	echo ""
;;
*)
echo "--> Hatalı bir seçenek seçtiniz."
esac
