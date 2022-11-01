# vpnsetup
cd vpnsetup
cp templates/config.template .
#change parameters in config watever you want
#the only vital parameters are PUBLIC_IP and VPN_IP
#you may leave everything else as is
./vpn.sh install
./vpn.sh configure
./vpn.sh start
./vpn.sh add #and follow the dialog
#then scp client config file from ./ccd to your machine and enjoy
