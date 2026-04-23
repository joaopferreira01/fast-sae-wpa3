# WPA3 SAE Setup Guide
---

## 🛑 Stop and Restart Network Manager

First, you need to stop the Network Manager to avoid conflicts:

```bash
sudo systemctl stop NetworkManager
sudo systemctl start NetworkManager
```
## 📡 Create Virtual Wi-Fi Interfaces

Load the mac80211_hwsim module to simulate two wireless radios:
```bash
sudo modprobe mac80211_hwsim radios=2
```
Check the created interfaces:
```bash
iw dev
```
Bring both interfaces up:
```bash
sudo ip link set wlan0 up
sudo ip link set wlan1 up
```
## 📶 Start Access Point (hostapd)

Run hostapd:
```bash
cd hostapd/hostapd-2.10/hostapd
sudo ./hostapd ap.conf 
```

## 📲 Start Client (wpa_supplicant)

In another terminal, start the client:
```bash
cd hostapd/wpa_supplicant-2.10/wpa_supplicant
sudo ./wpa_supplicant -i wlan1 -c sae.conf
```
## 🔄 Ticket-Based Reauthentication

To validate the ticket reauthentication after a successful connection:
```bash
sudo ./wpa_cli -i wlan1 flush
sudo ./wpa_cli -i wlan1 reconfigure
```
