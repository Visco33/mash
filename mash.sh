#!/bin/bash

TMP_FOLDER=$(mktemp -d)
CONFIG_FILE="mashcoin.conf"
MASH_DAEMON="/usr/local/bin/mashd"
MASH_REPO="https://github.com/mashcoinmn/mash-core"
DEFAULTMASHPORT=31372
DEFAULTMASHUSER="mash"
NODEIP=$(curl -s4 icanhazip.com)


RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


function compile_error() {
if [ "$?" -gt "0" ];
 then
  echo -e "${RED}Failed to compile $@. Please investigate.${NC}"
  exit 1
fi
}


function checks() {
if [[ $(lsb_release -d) != *16.04* ]]; then
  echo -e "${RED}You are not running Ubuntu 16.04. Installation is cancelled.${NC}"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}$0 must be run as root.${NC}"
   exit 1
fi

if [ -n "$(pidof $MASH_DAEMON)" ] || [ -e "$MASH_DAEMOM" ] ; then
  echo -e "${GREEN}\c"
  read -e -p "Mash is already installed. Do you want to add another MN? [Y/N]" NEW_MASH
  echo -e "{NC}"
  clear
else
  NEW_MASH="new"
fi
echo -e "${NC}"
apt-get update
apt-get upgrade
apt-get install libboost-system1.58.0
apt-get install libboost-filesystem1.58.0
apt-get install libboost-program-options1.58.0
apt-get install libboost-thread1.58.0
apt-get install libboost-chrono1.58.0
apt-get install libminiupnpc10
apt-get install libzmq5
apt-get install libevent-2.0-5
apt-get install libevent-pthreads-2.0-5
apt-get install pwgen
apt-get install bc
}

function prepare_system() {

echo -e "Prepare the system to install Mash master node."
apt-get update >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get update > /dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y -qq upgrade >/dev/null 2>&1
apt install -y software-properties-common >/dev/null 2>&1
echo -e "${GREEN}Adding bitcoin PPA repository"
apt-add-repository -y ppa:bitcoin/bitcoin >/dev/null 2>&1
echo -e "Installing required packages, it may take some time to finish.${NC}"
apt-get update >/dev/null 2>&1
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" make software-properties-common \
build-essential libtool autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev libboost-program-options-dev \
libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git wget pwgen curl libdb4.8-dev bsdmainutils libdb4.8++-dev \
libminiupnpc-dev libgmp3-dev ufw fail2ban >/dev/null 2>&1
clear
if [ "$?" -gt "0" ];
  then
    echo -e "${RED}Not all required packages were installed properly. Try to install them manually by running the following commands:${NC}\n"
    echo "apt-get update"
    echo "apt -y install software-properties-common"
    echo "apt-add-repository -y ppa:bitcoin/bitcoin"
    echo "apt-get update"
    echo "apt install -y make build-essential libtool software-properties-common autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev \
libboost-program-options-dev libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git pwgen curl libdb4.8-dev \
bsdmainutils libdb4.8++-dev libminiupnpc-dev libgmp3-dev ufw fail2ban "
 exit 1
fi

clear
echo -e "Checking if swap space is needed."
PHYMEM=$(free -g|awk '/^Mem:/{print $2}')
SWAP=$(free -g|awk '/^Swap:/{print $2}')
if [ "$PHYMEM" -lt "2" ] && [ -n "$SWAP" ]
  then
    echo -e "${GREEN}Server is running with less than 2G of RAM without SWAP, creating 2G swap file.${NC}"
    SWAPFILE=$(mktemp)
    dd if=/dev/zero of=$SWAPFILE bs=1024 count=2M
    chmod 600 $SWAPFILE
    mkswap $SWAPFILE
    swapon -a $SWAPFILE
else
  echo -e "${GREEN}Server running with at least 2G of RAM, no swap needed.${NC}"
fi
clear
}

function install_daemon() {
    echo -e "Download the debian package from Mash git.."
    wget https://github.com/mashcoinmn/mash-core/releases/download/Mash_1.0-4/mash-setup_1.0-4.deb
    sleep 2
    dpkg --install mash-setup_1.0-4.deb
#  RPCUSER=$(pwgen -s 8 1)
#  RPCPASSWORD=$(pwgen -s 15 1)
#    echo -e "${RED}rpcuser is${NC} $RPCUSER"
#    echo -e "${RED}rpcpassword is${NC} $RPCPASSWORD"
    DEFAULTMASHFOLDER="$HOME/.mashcoin"

#    PRIV_KEY=$(mash-cli masternode genkey)
#    echo -e "Masternode PrivKey is ${RED}$PRIV_KEY${NC}"
#    mash-cli stop
#    sleep 5
  myip=$(getMyIP)
    mkdir $DEFAULTMASHFOLDER
  cat << EOF > $DEFAULTMASHFOLDER/$CONFIG_FILE
rpcuser=RPCUSER
rpcpassword=RPCPASSWORD
rpcallowip=127.0.0.1
listen=1
server=1
daemon=1
txindex=1
#----
masternode=1
masternodeprivkey=7EsYztcecg8P7t3VsJxjNJbbzchG2MBa3hMgc8ZPD9BuDQgWKkE
masternodeaddr=$myip:31372

connect=144.202.106.140
connect=45.77.7.236
connect=140.82.51.140
connect=107.175.1.124
connect=107.175.1.123
connect=107.175.1.122
connect=198.46.177.120
connect=183.182.104.121
EOF
    sleep 5
    mashd
    sleep 5
}

function compile_node() {
  echo -e "Clone git repo and compile it. This may take some time. Press a key to continue."
  cd $TMP_FOLDER
  git clone https://github.com/Mash-Coin/MashCore
  cd MashCore
  chmod +x ./autogen.sh
  ./autogen.sh
  ./configure
  make
  ./tests
  make install
  clear

  cd $TMP_FOLDER
  git clone $MASH_REPO
  cd Mash/src
  make -f makefile.unix
  compile_error Mash
  chmod +x  mashd
  cp -a  mashd /usr/local/bin
  clear
  cd ~
  rm -rf $TMP_FOLDER
}

}

function enable_firewall() {
  echo -e "Installing fail2ban and setting up firewall to allow ingress on port ${GREEN}$MASHPORT${NC}"
  ufw allow $MASHPORT/tcp comment "MASH MN port" >/dev/null
  ufw allow $[MASHPORT-1]/tcp comment "MASH RPC port" >/dev/null
  ufw allow ssh comment "SSH" >/dev/null 2>&1
  ufw limit ssh/tcp >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  echo "y" | ufw enable >/dev/null 2>&1
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl start fail2ban >/dev/null 2>&1
}

function configure_systemd() {
  cat << EOF > /etc/systemd/system/$MASHUSER.service
[Unit]
Description=MASH service
After=network.target

[Service]
ExecStart=$MASH_DAEMON -conf=$MASHFOLDER/$CONFIG_FILE -datadir=$MASHFOLDER
ExecStop=$MASH_DAEMON -conf=$MASHFOLDER/$CONFIG_FILE -datadir=$MASHFOLDER stop
Restart=on-abort
User=$MASHUSER
Group=$MASHUSER

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  sleep 3
  systemctl start $MASHUSER.service
  systemctl enable $MASHUSER.service

  if [[ -z "$(ps axo user:15,cmd:100 | egrep ^$MASHUSER | grep $MASH_DAEMON)" ]]; then
    echo -e "${RED}MASH is not running${NC}, please investigate. You should start by running the following commands as root:"
    echo -e "${GREEN}systemctl start $MASHUSER.service"
    echo -e "systemctl status $MASHUSER.service"
    echo -e "less /var/log/syslog${NC}"
    exit 1
  fi
}

function ask_port() {
read -p "Mash Port: " -i $DEFAULTMASHPORT -e MASHPORT
: ${MASHPORT:=$DEFAULTMASHPORT}
}

function ask_user() {
  read -p "Mash user: " -i $DEFAULTMASHUSER -e MASHUSER
  : ${MASHUSER:=$DEFAULTMASHUSER}

  if [ -z "$(getent passwd $MASHUSER)" ]; then
    USERPASS=$(pwgen -s 12 1)
    useradd -m $MASHUSER
    echo "$MASHUSER:$USERPASS" | chpasswd

    MASHHOME=$(sudo -H -u $MASHUSER bash -c 'echo $HOME')
    DEFAULTMASHFOLDER="$MASHHOME/.mashcore"
    read -p "Configuration folder: " -i $DEFAULTMASHFOLDER -e MASHFOLDER
    : ${MASHFOLDER:=$DEFAULTMASHFOLDER}
    mkdir -p $MASHFOLDER
    chown -R $MASHUSER: $MASHFOLDER >/dev/null
  else
    clear
    echo -e "${RED}User exits. Please enter another username: ${NC}"
    ask_user
  fi
}

function check_port() {
  declare -a PORTS
  PORTS=($(netstat -tnlp | awk '/LISTEN/ {print $4}' | awk -F":" '{print $NF}' | sort | uniq | tr '\r\n'  ' '))
  ask_port

  while [[ ${PORTS[@]} =~ $MASHPORT ]] || [[ ${PORTS[@]} =~ $[MASHPORT-1] ]]; do
    clear
    echo -e "${RED}Port in use, please choose another port:${NF}"
    ask_port
  done
}

getMyIP() {
    local _ip _myip _line _nl=$'\n'
    while IFS=$': \t' read -a _line ;do
        [ -z "${_line%inet}" ] &&
           _ip=${_line[${#_line[1]}>4?1:2]} &&
           [ "${_ip#127.0.0.1}" ] && _myip=$_ip
      done< <(LANG=C /sbin/ifconfig)
    printf ${1+-v} $1 "%s${_nl:0:$[${#1}>0?0:1]}" $_myip
}

function create_config() {
#  RPCUSER=$(pwgen -s 8 1)
#  RPCPASSWORD=$(pwgen -s 15 1)
#    echo -e "${RED}rpcuser is${NC} $RPCUSER"
#    echo -e "${RED}rpcpassword is${NC} $RPCPASSWORD"
    DEFAULTMASHFOLDER="$HOME/.mashcoin"

    PRIV_KEY=$(mash-cli masternode genkey)
    echo -e "Masternode PrivKey is ${RED}$PRIV_KEY${NC}"
    mash-cli stop
    sleep 5
  myip=$(getMyIP)

  cat << EOF > $DEFAULTMASHFOLDER/$CONFIG_FILE
rpcuser=RPCUSER
rpcpassword=RPCPASSWORD
rpcallowip=127.0.0.1
listen=1
server=1
daemon=1
#----
masternode=1
masternodeprivkey=$PRIV_KEY
masternodeaddr=$myip:31372
txindex=1
connect=144.202.106.140
connect=45.77.7.236
connect=140.82.51.140
connect=107.175.1.124
connect=107.175.1.123
connect=107.175.1.122
connect=198.46.177.120
connect=183.182.104.121

EOF
    mashd
    sleep 5
    MASTERNODE_CONFIG_FILE="masternode.conf"
  read -e -p "Please input your masternode alias name:" MN_NAME
  outputs=$(mash-cli masternode outputs)
  a=${outputs#*\"}
  tr_hash=${a%%\"*}
  echo -e "Transaction hash is ${RED}$tr_hash${NC}"
  b=${a#*\"}
  b=${b#*\"}
  INDEX=${b%%\"*}

  myip=$(getMyIP)
  cat << EOF > $DEFAULTMASHFOLDER/$MASTERNODE_CONFIG_FILE
# Masternode config file
# Format: alias IP:port masternodeprivkey collateral_output_txid collateral_output_index
# Example: mn1 127.0.0.2:31372 93HaYBVUCYjEMeeH1Y4sBGLALQZE1Yc1K64xiqgX37tGBDQL8Xg 2bcd3c84c84f87eaa86e4e56834c92927a07f9e18718810b92e0d0324456a67c 0
$MN_NAME $myip:$DEFAULTMASHPORT $PRIV_KEY $tr_hash $INDEX

EOF
mash-cli stop
sleep 5
mashd
sleep 5
MNSYNCSTAT=1
echo -e "${GREEN} "
mash-cli masternode start-all
sleep 1
mash-cli masternode start-alias $MN_NAME
sleep 1
mash-cli masternode start
echo -e "${NC} "
}

function create_key() {
  echo -e "Enter your ${RED}Masternode Private Key${NC}. Leave it blank to generate a new ${RED}Masternode Private Key${NC} for you:"
  read -e MASHKEY
  if [[ -z "$MASHKEY" ]]; then
  su $MASHUSER -c "$MASH_DAEMON -conf=$MASHFOLDER/$CONFIG_FILE -datadir=$MASHFOLDER"
  sleep 5
  if [ -z "$(ps axo user:15,cmd:100 | egrep ^$MASHUSER | grep $MASH_DAEMON)" ]; then
   echo -e "${RED}Mash server couldn't start. Check /var/log/syslog for errors.{$NC}"
   exit 1
  fi
  MASHKEY=$(su $MASHUSER -c "$MASH_DAEMON -conf=$MASHFOLDER/$CONFIG_FILE -datadir=$MASHFOLDER masternode genkey")
  su $MASHUSER -c "$MASH_DAEMON -conf=$MASHFOLDER/$CONFIG_FILE -datadir=$MASHFOLDER stop"
fi
}

function update_config() {
  sed -i 's/daemon=1/daemon=0/' $MASHFOLDER/$CONFIG_FILE
  cat << EOF >> $MASHFOLDER/$CONFIG_FILE
maxconnections=256
masternode=1
masternodeaddr=$NODEIP:$MASHPORT
masternodeprivkey=$MASHKEY
EOF
  chown -R $MASHUSER: $MASHFOLDER >/dev/null
}

function important_information() {
 echo
 echo -e "================================================================================================================================"
 echo -e "Mash Masternode is up and running as user ${GREEN}$MASHUSER${NC} and it is listening on port ${GREEN}$MASHPORT${NC}."
 echo -e "${GREEN}$MASHUSER${NC} password is ${RED}$USERPASS${NC}"
 echo -e "Configuration file is: ${RED}$MASHFOLDER/$CONFIG_FILE${NC}"
 echo -e "Start: ${RED}systemctl start $MASHUSER.service${NC}"
 echo -e "Stop: ${RED}systemctl stop $MASHUSER.service${NC}"
 echo -e "VPS_IP:PORT ${RED}$NODEIP:$MASHPORT${NC}"
 echo -e "MASTERNODE PRIVATEKEY is: ${RED}$MASHKEY${NC}"
 echo -e "Please check Mash is running with the following command: ${GREEN}systemctl status $MASHUSER.service${NC}"
 echo -e "================================================================================================================================"
}


function create_masternode_config() {
    DEFAULTMASHFOLDER="$HOME/.mashcore"
    MASTERNODE_CONFIG_FILE="masternode.conf"
  read -e -p "Please input your masternode alias name:" MN_NAME
  outputs=$(mash-cli masternode outputs)
  a=${outputs#*\"}
  tr_hash=${a%%\"*}
  echo -e "Transaction hash is ${RED}$tr_hash${NC}"
  PRIV_KEY=$(mash-cli masternode genkey)
  IP_COMMAND="ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'"
  IP_ADDRESS=$($IP_COMMAND)
    echo $IP_ADDRESS
  cat << EOF > $DEFAULTMASHFOLDER/$MASTERNODE_CONFIG_FILE
$MN_NAME $IP_ADDRESS:$DEFAULTMASHPORT $PRIV_KEY $tr_hash 0

EOF
  mash-cli masternode start-alias $MN_NAME
    echo -e "${NC}"
}

function setup_node() {
#  ask_user
#  check_port
  wait_collateral
  create_config
#  create_masternode_config
#  create_key
#  update_config
#  enable_firewall
#  configure_systemd
#  important_information
}


##### Main #####
clear

checks
if [[ ("$NEW_MASH" == "y" || "$NEW_MASH" == "Y") ]]; then
  setup_node
  exit 0
elif [[ "$NEW_MASH" == "new" ]]; then
#  prepare_system
#  compile_node
  install_daemon
  setup_node
else
  echo -e "${GREEN}Mash already running.${NC}"
  exit 0
fi
