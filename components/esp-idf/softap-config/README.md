#Wifi softAP config -esp-idf
Library for esp-idf to bootstrap WiFi-enabled accessories WiFi config

 When you initialize it
it tries to connect to configured WiFi network. If no configuration exists or
network is not available, it starts it's own WiFi AP (with given name and
optional password). AP runs a captive portal, so when user connects to it a
popup window is displayed asking user to select one of WiFi networks that are
present in that location (and a password if network is secured) and configures
device to connect to that network.

After successful connection it calls provided callback so you can continue
accessory initializiation.