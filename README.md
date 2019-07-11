# WLANSniff

partielle Code-Auszüge eines WLAN Sniffers.
Überwacht Wireless Kanäle und gibt empfangene Pakete bzw. Statistiken aus.
(Entwickelt als internes Modul von "Ollerus")


Argumente:
wlanmonitor [channel-specification]
WLAN Traffic Monitor standalone execution.
-> 2GHz - Monitors the 2.4GHz Spectrum. It starts at channel 1 and loops over the whole 2.4GHz Band. As the distance between the channels it uses the value specified in the cfg-File.
-> 5GHz [optional further spec]  - Monitors the 5GHz Spectrum. The exactly used channel-range can be further specified with additional arguments.
-->> eu  - The allowed channels in the EU.
-->> eulower
-->> euupper
-->> usa
-->> usalower
-->> usaupper
-->> jp
-->> nodfs
Start “ollerus absint wlanmonitor 5GHz” for a more detailed printout on the terminal!

-> chan [channel list]
Exactly gives the WLAN Monitor a list of the channels to observe, separated by “,” (without Blanks/whitespaces).
Bsp.: wlanmonitor 1,5,36
