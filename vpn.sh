#!/bin/bash
##########################################################################################################
source ./config
source ./utils.sh
##########################################################################################################
ARG=${1}
##########################################################################################################
function set_environment() {
	# Find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi
	local SCRIPTPATH=$(get_script_path)
	if [ ! -d ${SCRIPTPATH}/easy-rsa ]; then
		echo "easy-rsa not detected, trying to download..."
		$(cd ${SCRIPTPATH} && install_easy_rsa_from_source)
	fi
	if [ ! -d ${SCRIPTPATH}/easy-rsa ]; then
		echo "failed. Aborting."
		exit 1
	else
		echo "OK. Proceeding."
	fi
	EASYRSA_PATH=${SCRIPTPATH}/easy-rsa
	EASYRSA_BIN="${EASYRSA_PATH}/easyrsa --vars=${WORKDIR}/vars"
}
##########################################################################################################
function test() {
	echo "test"
}
##########################################################################################################
if [ -z ${ARG} ]; then
	echo "no action specified" 
	exit 0
fi
initialCheck
set_environment
case ${ARG} in
	install)
		install_prerequisites
		;;
	configure)
		configure_openvpn_server
		;;
	start)
		start_vpnserver
		;;
	stop)
		stop_vpnserver
		;;
	add)
		add_client
		;;
	test)
		test
		;;
	*) 
		echo "unknown or absent argument"
		exit 0
		;;
esac
##########################################################################################################
