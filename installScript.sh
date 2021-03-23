#!/bin/bash
##### shadowsocks #####
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#Current folder
cur_dir=`pwd`

# Make sure only root can run our script
rootness(){
    if [[ $EUID -ne 0 ]]; then
        echo "Error:This script must be run as root!" 1>&2
        exit 1
    fi
}

# Disable selinux
disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

#Check system
check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif cat /etc/issue | grep -Eqi "debian"; then
        release="debian"
        systemPackage="apt"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        release="ubuntu"
        systemPackage="apt"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
        systemPackage="yum"
    elif cat /proc/version | grep -Eqi "debian"; then
        release="debian"
        systemPackage="apt"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        release="ubuntu"
        systemPackage="apt"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ ${checkType} == "sysRelease" ]]; then
        if [ "$value" == "$release" ]; then
            return 0
        else
            return 1
        fi
    elif [[ ${checkType} == "packageManager" ]]; then
        if [ "$value" == "$systemPackage" ]; then
            return 0
        else
            return 1
        fi
    fi
}

# Get version
getversion(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

# CentOS version
centosversion(){
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

# Get public IP address
get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    [ ! -z ${IP} ] && echo ${IP} || echo
}

# Pre-installation settings
pre_install(){
    if check_sys packageManager yum || check_sys packageManager apt; then
        # Not support CentOS 5
        if centosversion 5; then
            echo "Error: Not supported CentOS 5, please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
            exit 1
        fi
    else
        echo "Error: Your OS is not supported. please change OS to CentOS/Debian/Ubuntu and try again."
        exit 1
    fi
    # Set shadowsocks config password
    shadowsockspwd="teddysun"

    # Set shadowsocks config port
    shadowsocksport="8989"

    echo
    echo "Press any key to start...or Press Ctrl+C to cancel"
    #Install necessary dependencies
    if check_sys packageManager yum; then
        yum install -y unzip openssl-devel gcc swig python python-devel python-setuptools autoconf libtool libevent automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel
    elif check_sys packageManager apt; then
        apt-get -y update
        apt-get -y install python python-dev python-pip python-setuptools python-m2crypto curl wget unzip gcc swig automake make perl cpio build-essential
    fi
    cd ${cur_dir}
}

# Download files
download_files(){
    # Download libsodium file
    if ! wget --no-check-certificate -O libsodium-1.0.12.tar.gz https://github.com/jedisct1/libsodium/releases/download/1.0.12/libsodium-1.0.12.tar.gz; then
        echo "Failed to download libsodium-1.0.12.tar.gz!"
        exit 1
    fi
    # Download Shadowsocks file
    if ! wget --no-check-certificate -O shadowsocks-master.zip https://github.com/shadowsocks/shadowsocks/archive/master.zip; then
        echo "Failed to download shadowsocks python file!"
        exit 1
    fi
    # Download Shadowsocks init script
    if check_sys packageManager yum; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks -O /etc/init.d/shadowsocks; then
            echo "Failed to download shadowsocks chkconfig file!"
            exit 1
        fi
    elif check_sys packageManager apt; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-debian -O /etc/init.d/shadowsocks; then
            echo "Failed to download shadowsocks chkconfig file!"
            exit 1
        fi
    fi
}

# Config shadowsocks
config_shadowsocks(){
    cat > /etc/shadowsocks.json<<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":300,
    "method":"aes-256-cfb",
    "fast_open":false
}
EOF
}

# Firewall set
firewall_set(){
    echo "firewall set start..."
    if centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep -i ${shadowsocksport} > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo "port ${shadowsocksport} has been set up."
            fi
        else
            echo "WARNING: iptables looks like shutdown or not installed, please manually set it if necessary."
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/tcp
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/udp
            firewall-cmd --reload
        else
            echo "Firewalld looks like not running, try to start..."
            systemctl start firewalld
            if [ $? -eq 0 ]; then
                firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/tcp
                firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/udp
                firewall-cmd --reload
            else
                echo "WARNING: Try to start firewalld failed. please enable port ${shadowsocksport} manually if necessary."
            fi
        fi
    fi
    echo "firewall set completed..."
}

# Install Shadowsocks
install(){
    # Install libsodium
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${cur_dir}
        tar zxf libsodium-1.0.12.tar.gz
        cd libsodium-1.0.12
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo "libsodium install failed!"
            install_cleanup
            exit 1
        fi
    fi

    ldconfig
    # Install Shadowsocks
    cd ${cur_dir}
    unzip -q shadowsocks-master.zip
    if [ $? -ne 0 ];then
        echo "unzip shadowsocks-master.zip failed! please check unzip command."
        install_cleanup
        exit 1
    fi

    cd ${cur_dir}/shadowsocks-master
    python setup.py install --record /usr/local/shadowsocks_install.log

    if [ -f /usr/bin/ssserver ] || [ -f /usr/local/bin/ssserver ]; then
        chmod +x /etc/init.d/shadowsocks
        if check_sys packageManager yum; then
            chkconfig --add shadowsocks
            chkconfig shadowsocks on
        elif check_sys packageManager apt; then
            update-rc.d -f shadowsocks defaults
        fi
        /etc/init.d/shadowsocks start
    else
        echo
        echo "Shadowsocks install failed! please visit https://teddysun.com/342.html and contact."
        install_cleanup
        exit 1
    fi

    clear
    echo
    echo "Congratulations, shadowsocks server install completed!"
    echo -e "Your Server IP: \033[41;37m $(get_ip) \033[0m"
    echo -e "Your Server Port: \033[41;37m ${shadowsocksport} \033[0m"
    echo -e "Your Password: \033[41;37m ${shadowsockspwd} \033[0m"
    echo -e "Your Local IP: \033[41;37m 127.0.0.1 \033[0m"
    echo -e "Your Local Port: \033[41;37m 1080 \033[0m"
    echo -e "Your Encryption Method: \033[41;37m aes-256-cfb \033[0m"
    echo
    echo "Welcome to visit:https://teddysun.com/342.html"
    echo "Enjoy it!"
    echo
}

# Install cleanup
install_cleanup(){
    cd ${cur_dir}
    rm -rf shadowsocks-master.zip shadowsocks-master libsodium-1.0.12.tar.gz libsodium-1.0.12
}

# Uninstall Shadowsocks
uninstall_shadowsocks(){
    printf "Are you sure uninstall Shadowsocks? (y/n) "
    printf "\n"
    read -p "(Default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ps -ef | grep -v grep | grep -i "ssserver" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            /etc/init.d/shadowsocks stop
        fi
        if check_sys packageManager yum; then
            chkconfig --del shadowsocks
        elif check_sys packageManager apt; then
            update-rc.d -f shadowsocks remove
        fi
        # delete config file
        rm -f /etc/shadowsocks.json
        rm -f /var/run/shadowsocks.pid
        rm -f /etc/init.d/shadowsocks
        rm -f /var/log/shadowsocks.log
        if [ -f /usr/local/shadowsocks_install.log ]; then
            cat /usr/local/shadowsocks_install.log | xargs rm -rf
        fi
        echo "Shadowsocks uninstall success!"
    else
        echo
        echo "uninstall cancelled, nothing to do..."
        echo
    fi
}

# Install Shadowsocks-python
install_shadowsocks(){
    rootness
    disable_selinux
    pre_install
    download_files
    config_shadowsocks
    if check_sys packageManager yum; then
        firewall_set
    fi
    install
    install_cleanup
}

# Initialization step
action=$1
[ -z $1 ] && action=install
case "$action" in
    install|uninstall)
        ${action}_shadowsocks
        ;;
    *)
        echo "Arguments error! [${action}]"
        echo "Usage: `basename $0` [install|uninstall]"
    ;;
esac

##### serverspeeder ######
#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH


#定义变量
#授权文件自动生成url
APX=http://rs.91yun.pw/apx1.php
#安装包下载地址
INSTALLPACK=https://github.com/91yun/serverspeeder/blob/test/91yunserverspeeder.tar.gz?raw=true
#判断版本支持情况的地址
CHECKSYSTEM=https://raw.githubusercontent.com/91yun/serverspeeder/test/serverspeederbin.txt
#bin下载地址
BINURL=http://rs.91yun.pw/



#取操作系统的名称
Get_Dist_Name()
{
    if grep -Eqi "CentOS" /etc/issue || grep -Eq "CentOS" /etc/*-release; then
        release='CentOS'
        PM='yum'
    elif grep -Eqi "Debian" /etc/issue || grep -Eq "Debian" /etc/*-release; then
        release='Debian'
        PM='apt'
    elif grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then
        release='Ubuntu'
        PM='apt'		
	else
        release='unknow'
    fi
    
}

Get_OS_Bit()
{
    if [[ `getconf WORD_BIT` = '32' && `getconf LONG_BIT` = '64' ]] ; then
        bit='x64'
    else
        bit='x32'
    fi
}

Get_Dist_Name
Get_OS_Bit
kernel=`uname -r`
kernel_result=""

echo -e "\r\n"
echo "===============System Info======================="
echo "$release "
echo "$kernel "
echo "$bit "
echo "================================================="
echo -e "\r\n"

#下周支持的内核库
wget $CHECKSYSTEM --no-check-certificate -O serverspeederbin.txt || { echo "Error downloading file, please try again later.";exit 1; }

#判断是否有完全匹配的内核
grep -q "$release/[^/]*/$kernel/$bit" serverspeederbin.txt
if [ $? -eq 0 ]; then
	#如果完全匹配，则取的内核版本
	kernel_result=$kernel
else
	#如果没有完全匹配的内核，则开始模糊匹配
	echo ">>>This kernel is not supported. Trying fuzzy matching..."
	echo -e "\r\n"
	#因为centos和ubuntu的版本号不太一样，所以centos匹配2.6.32-504.el6.x86_64到504 ，
	if [ "$release" == "CentOS" ]; then
		kernel1=`echo $kernel | awk -F '-' '{ print $1 }'`
		kernel2=`echo $kernel | awk -F '-' '{ print $2 }' | awk -F '.' '{ print $1 }'`
	elif [[ "$release" == "Ubuntu" ]] || [[ "$release" == "Debian" ]]; then
		kernel1=`echo $kernel | awk -F '-' '{ print $1 }'`
		kernel2=`echo $kernel | awk -F '-' '{ print $2 }'`
	else
		echo "This script only supports CentOS, Ubuntu and Debian."
		exit 1
	fi
	
	grep -q "$release/[^/]*/$kernel1\(-\)\{0,1\}$kernel2[^/]*/$bit" serverspeederbin.txt
	if [ $? -eq 1 ]; then
			echo -e "\r\n"
			echo -e "Serverspeeder is not supported on this kernel! View all supported systems and kernels here:\033[41;37m https://www.91yun.org/serverspeeder91yun \033[0m"
			exit 1
	else
		#如果模糊匹配到了，就给玩家选
		echo "There is no exact match for this kernel, please choose the closest one below:"
		echo -e "The current kernel is \033[41;37m $kernel \033[0m"
		echo -e "\r\n"
		cat serverspeederbin.txt | grep  "$release/[^/]*/$kernel1\(-\)\{0,1\}$kernel2[^/]*/$bit"  | awk -F '/' '{ print NR"："$3 }'
		# echo -e "\r\n"
		# echo "Please enter the number of your option："	
		# read cver2
		# if [ "$cver2" == "" ]; then
		# 	echo "You did not choose any kernel options. Installation terminated."
		# 	exit 1
		# fi
		# echo -e "\r\n"
        cver2=1
		cver2str="cat serverspeederbin.txt | grep  \"$release/[^/]*/$kernel1\(-\)\{0,1\}$kernel2[^/]*/$bit\"  | awk -F '/' '{ print NR\"：\"\$3 }' | awk -F '：' '/"$cver2："/{ print \$2 }' | awk 'NR==1{print \$1}'"
		kernel_result=$(eval $cver2str)			
	fi
fi

if [ "$kernel_result" == "" ]; then
	echo "Unable to get kernel information. Installtion terminated."
	exit 1
fi

echo "Installing ServerSpeeder, please wait for a moment..."


#开始匹配锐速的版本
serverspeederver=3.10.61.0

grep -q "$release/[^/]*/$kernel_result/$bit/$serverspeederver" serverspeederbin.txt
if [ $? == 1 ]; then
	#如果没有匹配到这个版本的锐速，则取第一个
	serverspeederverstr="grep \"$release/[^/]*/$kernel_result/$bit/\" serverspeederbin.txt | awk -F '/' 'NR==1{print \$5}'"
	serverspeederver=$(eval $serverspeederverstr)
fi



BINFILESTR="cat serverspeederbin.txt | grep '$release/[^/]*/$kernel_result/$bit/$serverspeederver/0' | awk -F '/' '{ print \$1\"/\"\$2\"/\"\$3\"/\"\$4\"/\"\$5\"/\"\$7 }'"
BINFILE=$(eval $BINFILESTR)
if [ "$BINFILE" == "" ]; then
	echo "Unable to get BINFILE. Installation terminated."
	exit 1
fi
BIN=${BINURL}${BINFILE}
rm -rf serverspeederbin.txt





if [ "$1" == "" ]; then
	MACSTR="LANG=C ifconfig eth0 | awk '/HWaddr/{ print \$5 }' "
	MAC=$(eval $MACSTR)
	if [ "$MAC" == "" ]; then
		MACSTR="LANG=C ifconfig eth0 | awk '/ether/{ print \$2 }' "
		MAC=$(eval $MACSTR)
	fi	
	if [ "$MAC" == "" ]; then
		echo "The name of network interface is not eth0, please retry after changing the name."
		exit 1
	fi
else
	MAC=$1
fi	

#如果自动取不到就退出
if [ "$MAC" = "" ]; then
	echo "Unable to get MAC address. Installation terminated."
	exit 1
fi

	
#下载安装包
wget -N --no-check-certificate -O 91yunserverspeeder.tar.gz  $INSTALLPACK 
tar xfvz 91yunserverspeeder.tar.gz || { echo "Unable to download Installation package. Installation terminated.";exit 1; }

#下载授权文件
wget -N --no-check-certificate -O apx.lic "$APX?mac=$MAC" || { echo "Unable to download lic file, please check: $APX?mac=$MAC";exit 1;}
mv apx.lic 91yunserverspeeder/apxfiles/etc/


#取得序列号

wget -N --no-check-certificate -O serverspeedersn.txt "$APX?mac=$MAC&sno"
SNO=$(cat serverspeedersn.txt)
rm -rf serverspeedersn.txt
sed -i "s/serial=\"sno\"/serial=\"$SNO\"/g" 91yunserverspeeder/apxfiles/etc/config
sed -i "s/apx-20341231/apx/g" 91yunserverspeeder/apxfiles/etc/config
rv=$release"_"$kernel_result
sed -i "s/acce-3.10.61.0-\[Debian_7_3.2.0-4-amd64\]/acce-$serverspeederver-[$rv]/g" 91yunserverspeeder/apxfiles/etc/config

#下载bin文件;
wget -N --no-check-certificate -O "acce-"$serverspeederver"-["$release"_"$kernel_result"]" $BIN 
mv "acce-"$serverspeederver"-["$release"_"$kernel_result"]" 91yunserverspeeder/apxfiles/bin/

#切换目录执安装文件
cd 91yunserverspeeder
bash install.sh

#禁止修改授权文件
#chattr +i /serverspeeder/etc/apx*
bash /serverspeeder/bin/serverSpeeder.sh status