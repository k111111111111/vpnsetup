#!/bin/bash
##########################################################################################################
function get_script_path() {
	local SOURCE=${BASH_SOURCE[0]}
	while [ -L "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
	  local DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )
	  SOURCE=$(readlink "$SOURCE")
	  [[ $SOURCE != /* ]] && SOURCE=$DIR/$SOURCE # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
	done
	DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )
	echo $DIR
}
##########################################################################################################
function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}
##########################################################################################################
function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		echo "TUN is not available, check if module present..."
		mkdir /dev/net
		mknod /dev/net/tun c 10 200
		return 1
	fi
}
##########################################################################################################
function initialCheck() {
	if ! isRoot; then
		echo "Sorry, you need to run this as root"
		exit 1
	fi
	if ! tunAvailable; then
		echo "TUN is not available"
		exit 1
	fi
}
##########################################################################################################
function IPprefix_by_netmask() {
    #function returns prefix for given netmask in arg1
    bits=0
    for octet in $(echo $1| sed 's/\./ /g'); do 
         binbits=$(echo "obase=2; ibase=10; ${octet}"| bc | sed 's/0//g') 
         let bits+=${#binbits}
    done
    echo "${bits}"
}
##########################################################################################################
function install_easy_rsa_from_source {
	# Install the latest version of easy-rsa from source, if not already installed.
	local version="3.0.7"
	wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
	mkdir -p ./easy-rsa
	tar xzf ~/easy-rsa.tgz --strip-components=1 --directory ./easy-rsa
	rm -f ~/easy-rsa.tgz
}
##########################################################################################################
function check_package() {
	local name=${1}
	local pack=$(apt search "^${name}$" 2>/dev/null)
	local installed=false
	local pattern="^${name}\/.*installed"
	while read -r line
	do
		if [[ ${line} =~ ${pattern} ]]; then
			installed=true
		fi
	done<<<${pack}
	echo ${installed}
}
##########################################################################################################
function install_package() {
	local name=${1}
	apt install ${name}
	local res=$?
	if [ ${res} != 0 ]; then
		echo "failed to install ${name}"
		exit -1
	else
		echo "${name} successfully installed"
	fi
}
##########################################################################################################
function install_prerequisites() {
	local package_list=("openvpn" "iptables" "openssl" "ca-certificates" "wget" "tar" "mlocate" "curl" "bc")
	for package in ${package_list[@]}
	do
		local installed=$(check_package ${package})
		if [ ${installed} != true ]; then
			install_package ${package}
		else
			echo "${package} already installed"
		fi
	done
	updatedb
}
##########################################################################################################
function create_server_config_file() {
	cp templates/server.conf.template ${WORKDIR}/${SERVER_NAME}.conf
	local FILE=${WORKDIR}/${SERVER_NAME}.conf
	sed -i "s/%%%PORT%%%/${PORT}/g" ${FILE}
	sed -i "s/%%%PROTOCOL%%%/${PROTOCOL}/g" ${FILE}
	sed -i "s/%%%NOGROUP%%%/${NOGROUP}/g" ${FILE}
	sed -i "s/%%%VPN_IP%%%/${VPN_IP}/g" ${FILE}
	sed -i "s/%%%VPN_SUBNET_MASK%%%/${VPN_SUBNET_MASK}/g" ${FILE}
	sed -i "s/%%%DNS1%%%/${DNS1}/g" ${FILE}
	sed -i "s/%%%DNS2%%%/${DNS2}/g" ${FILE}
	if [ ${COMPRESSION_ENABLED} == "y" ]; then
		local COMPRESSION_PARAM="compress ${COMPRESSION_ALG}"
		sed -i "s/%%%COMPRESSION_PARAM%%%/${COMPRESSION_PARAM}/g" ${FILE}
	else
		sed -i "s/%%%COMPRESSION_PARAM%%%/ /g" ${FILE}
	fi
	if [[ $DH_TYPE == "ECDH" ]]; then
		local DH_DEFINITION="dh none\necdh-curve ${DH_CURVE}"
		sed -i "s/%%%DH_DEFINITION%%%/${DH_DEFINITION}/g" ${FILE}			
	elif [[ $DH_TYPE == "DH" ]]; then
		local DH_DEFINITION="dh dh.pem"
		sed -i "s/%%%DH_DEFINITION%%%/${DH_DEFINITION}/g" ${FILE}
	fi
	case $TLS_SIG in
	tls-crypt)
		local TLS_PARAM="tls-crypt tls-crypt.key"
		sed -i "s/%%%TLS_PARAM%%%/${TLS_PARAM}/g" ${FILE}
		;;
	tls-auth)
		local TLS_PARAM="tls-auth tls-auth.key 0"
		sed -i "s/%%%TLS_PARAM%%%/${TLS_PARAM}/g" ${FILE}
		;;
	esac
	sed -i "s/%%%SERVER_NAME%%%/${SERVER_NAME}/g" ${FILE}
	sed -i "s/%%%HMAC_ALG%%%/${HMAC_ALG}/g" ${FILE}
	sed -i "s/%%%CIPHER%%%/${CIPHER}/g" ${FILE}
	sed -i "s/%%%CC_CIPHER%%%/${CC_CIPHER}/g" ${FILE}
	#sed -i "s:%%%WORKDIR%%%:${WORKDIR}:g" ${FILE}
	if [ ! -d ${WORKDIR}/logs ]; then
		mkdir -p ${WORKDIR}/logs
	fi
}
##########################################################################################################
function configure_openvpn_server() {
	# Detect public IPv4 address and pre-fill for the user
	#IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	#if behind NAT and public ip not set
	if [ -z ${PUBLIC_IP} ]; then
		echo "trying to detect public ip"
		PUBLIC_IP=$(curl --retry 5 --retry-connrefused -4 https://ifconfig.co)
		if [ -z ${PUBLIC_IP} ]; then
			echo "public ip ${PUBLIC_IP} detected"
		else
			echo "failed to detect public ip"
			exit 0
		fi
	fi
	# Get the "public" interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

	# $NIC can not be empty for iptables scripts
	if [[ -z $NIC ]]; then
		echo
		echo "public interface not set"
		echo "This is needed to setup MASQUERADE."
		exit 0
	fi

	mkdir -p ${WORKDIR}
	case $CERT_TYPE in
	ECDSA)
		echo "set_var EASYRSA_ALGO ec" >${WORKDIR}/vars
		echo "set_var EASYRSA_CURVE $CERT_CURVE" >>${WORKDIR}/vars
		;;
	RSA)
		echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >${WORKDIR}/vars
		;;
	esac

	# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
	SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	echo "$SERVER_CN" >${WORKDIR}/SERVER_CN_GENERATED
	#if [ -z ${SERVER_NAME} ]; then
	#	SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	#fi
	echo "$SERVER_NAME" >${WORKDIR}/SERVER_NAME_GENERATED

	echo "set_var EASYRSA_REQ_CN $SERVER_CN" >>${WORKDIR}/vars
	echo "set_var EASYRSA_PKI ${EASYRSA_PKI}" >>${WORKDIR}/vars
	# Create the PKI, set up the CA, the DH params and the server certificate
	${EASYRSA_BIN} init-pki
	${EASYRSA_BIN} --batch build-ca nopass

	if [[ $DH_TYPE == "DH" ]]; then
		# ECDH keys are generated on-the-fly so we don't need to generate them beforehand
		openssl dhparam -out ${WORKDIR}/dh.pem $DH_KEY_SIZE
	fi

	${EASYRSA_BIN} build-server-full "$SERVER_NAME" nopass
	EASYRSA_CRL_DAYS=3650 ${EASYRSA_BIN} gen-crl

	case $TLS_SIG in
	tls-crypt)
		# Generate tls-crypt key
		openvpn --genkey --secret ${WORKDIR}/tls-crypt.key
		;;
	tls-auth)
		# Generate tls-auth key
		openvpn --genkey --secret ${WORKDIR}/tls-auth.key
		;;
	esac

	# Move all the generated files
	cp ${WORKDIR}/pki/ca.crt ${WORKDIR}/pki/private/ca.key "${WORKDIR}/pki/issued/$SERVER_NAME.crt" "${WORKDIR}/pki/private/$SERVER_NAME.key" \
									${WORKDIR}/pki/crl.pem ${WORKDIR}
	# Make cert revocation list readable for non-root
	chmod 644 ${WORKDIR}/crl.pem
	# Enable routing
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	# Apply sysctl rules
	sysctl --system
	#create server configuration file
	create_server_config_file
	create_client_template
	# Create client-config-dir dir
	mkdir -p ${WORKDIR}/ccd
	#copy necessary files
	local VPN_CIDR=$(IPprefix_by_netmask ${VPN_SUBNET_MASK})
	echo "CIDR = ${VPN_CIDR}"
	cp templates/iptables_add_rules.sh.template ${WORKDIR}/iptables_add_rules.sh
	local FILE=${WORKDIR}/iptables_add_rules.sh
	chmod +x ${FILE}
	sed -i "s/%%%VPN_IP%%%/${VPN_IP}/g" ${FILE}
	sed -i "s/%%%VPN_CIDR%%%/${VPN_CIDR}/g" ${FILE}
	sed -i "s/%%%NIC%%%/${NIC}/g" ${FILE}
	sed -i "s/%%%PROTOCOL%%%/${PROTOCOL}/g" ${FILE}
	sed -i "s/%%%PORT%%%/${PORT}/g" ${FILE}
	cp templates/iptables_remove_rules.sh.template ${WORKDIR}/iptables_remove_rules.sh
	FILE=${WORKDIR}/iptables_remove_rules.sh
	chmod +x ${FILE}
	sed -i "s/%%%VPN_IP%%%/${VPN_IP}/g" ${FILE}
	sed -i "s/%%%VPN_CIDR%%%/${VPN_CIDR}/g" ${FILE}
	sed -i "s/%%%NIC%%%/${NIC}/g" ${FILE}
	sed -i "s/%%%PROTOCOL%%%/${PROTOCOL}/g" ${FILE}
	sed -i "s/%%%PORT%%%/${PORT}/g" ${FILE}
	cp templates/openvpn.service.template /etc/systemd/system/openvpn-${SERVER_NAME}.service
	FILE=/etc/systemd/system/openvpn-${SERVER_NAME}.service
	sed -i "s/%%%SERVER_NAME%%%/${SERVER_NAME}/g" ${FILE}
	sed -i "s:%%%WORKDIR%%%:${WORKDIR}:g" ${FILE}
}
##########################################################################################################
function start_vpnserver() {
	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable openvpn-${SERVER_NAME}
	systemctl start openvpn-${SERVER_NAME}
}
##########################################################################################################
function stop_vpnserver() {
	# Enable service and apply rules
	systemctl stop openvpn-${SERVER_NAME}
	systemctl disable openvpn-${SERVER_NAME}
}
##########################################################################################################
function create_client_template() {
	cp templates/client.conf.template ${WORKDIR}/client.template
	local FILE=${WORKDIR}/client.template
	sed -i "s/%%%PORT%%%/${PORT}/g" ${FILE}
	sed -i "s/%%%PUBLIC_IP%%%/${PUBLIC_IP}/g" ${FILE}
	sed -i "s/%%%SERVER_NAME%%%/${SERVER_NAME}/g" ${FILE}
	if [ ${PROTOCOL} == "udp" ]; then
		local PROTOCOL_PARAM="proto udp\nexplicit-exit-notify"
		sed -i "s/%%%PROTOCOL_PARAM%%%/${PROTOCOL_PARAM}/g" ${FILE}
	elif [ ${PROTOCOL} == "tcp" ]; then
		local PROTOCOL_PARAM="proto tcp-client"
		sed -i "s/%%%PROTOCOL_PARAM%%%/${PROTOCOL_PARAM}/g" ${FILE}
	fi
	sed -i "s/%%%HMAC_ALG%%%/${HMAC_ALG}/g" ${FILE}
	sed -i "s/%%%CIPHER%%%/${CIPHER}/g" ${FILE}
	sed -i "s/%%%CC_CIPHER%%%/${CC_CIPHER}/g" ${FILE}
	if [ ${COMPRESSION_ENABLED} == "y" ]; then
		local COMPRESSION_PARAM="compress ${COMPRESSION_ALG}"
		sed -i "s/%%%COMPRESSION_PARAM%%%/${COMPRESSION_PARAM}/g" ${FILE}
	else
		sed -i "s/%%%COMPRESSION_PARAM%%%/ /g" ${FILE}
	fi
}
##########################################################################################################
function add_client() {
	echo ""
	echo "Tell me a name for the client."
	echo "The name must consist of alphanumeric character. It may also include an underscore or a dash."

	until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
		read -rp "Client name: " -e CLIENT
	done

	echo ""
	echo "Do you want to protect the configuration file with a password?"
	echo "(e.g. encrypt the private key with a password)"
	echo "   1) Add a passwordless client"
	echo "   2) Use a password for the client"

	until [[ $PASS =~ ^[1-2]$ ]]; do
		read -rp "Select an option [1-2]: " -e -i 1 PASS
	done

	CLIENTEXISTS=$(tail -n +2 ${EASYRSA_PATH}/pki/index.txt | grep -c -E "/CN=${CLIENT}\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		echo ""
		echo "The specified client CN was already found in easy-rsa, please choose another name."
		exit
	else
		case $PASS in
		1)
			${EASYRSA_BIN} build-client-full "${CLIENT}" nopass
			;;
		2)
			echo "⚠️ You will be asked for the client password below ⚠️"
			${EASYRSA_BIN} build-client-full "${CLIENT}"
			;;
		esac
		echo "Client ${CLIENT} added."
	fi

	# Home directory of the user, where the client configuration will be written
	homeDir=${WORKDIR}/ccd

	# Determine if we use tls-auth or tls-crypt
	if grep -qs "^tls-crypt" ${WORKDIR}/${SERVER_NAME}.conf; then
		TLS_SIG="1"
	elif grep -qs "^tls-auth" ${WORKDIR}/${SERVER_NAME}.conf; then
		TLS_SIG="2"
	fi

	# Generates the custom client.ovpn
	cp ${WORKDIR}/client.template "${homeDir}/${CLIENT}.conf"
	{
		echo "<ca>"
		cat "${WORKDIR}/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END/' "${WORKDIR}/pki/issued/${CLIENT}.crt"
		echo "</cert>"

		echo "<key>"
		cat "${WORKDIR}/pki/private/${CLIENT}.key"
		echo "</key>"

		case $TLS_SIG in
		1)
			echo "<tls-crypt>"
			cat ${WORKDIR}/tls-crypt.key
			echo "</tls-crypt>"
			;;
		2)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat ${WORKDIR}/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"${homeDir}/${CLIENT}.conf"
	cp ${homeDir}/${CLIENT}.conf ${homeDir}/${CLIENT}.ovpn
	echo ""
	echo "The configuration file has been written to $homeDir/$CLIENT.ovpn."
	echo "Download the .ovpn/.conf file and import it in your OpenVPN client."
}
##########################################################################################################
