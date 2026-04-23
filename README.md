sudo systemctl stop NetworkManager
sudo systemctl start NetworkManager

sudo modprobe mac80211_hwsim radios=2
iw dev
sudo ip link set wlan0 up
sudo ip link set wlan1 up


sudo ./hostapd ap.conf -ddK
sudo ./wpa_supplicant -i wlan1 -c sae.conf -dd


sudo ./wpa_cli -i wlan1 flush
sudo ./wpa_cli -i wlan1 reconfigure
