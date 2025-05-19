#!/bin/bash
#################### x-ui ##################################
[[ $EUID -ne 0 ]] && { echo "not root!"; exec sudo "$0" "$@"; }
msg()     { echo -e "\e[1;37;40m $1 \e[0m";}
msg_ok()  { echo -e "\e[1;32;40m $1 \e[0m";}
msg_err() { echo -e "\e[1;31;40m $1 \e[0m";}
msg_inf() { echo -e "\e[1;36;40m $1 \e[0m";}
msg_war() { echo -e "\e[1;33;40m $1 \e[0m";}
hrline() { printf '\033[1;35;40m%s\033[0m\n' "$(printf '%*s' "${COLUMNS:-$(tput cols)}" '' | tr ' ' "${1:--}")"; }

##################################Random Port and Path ###################################################
mkdir -p ${HOME}/.cache
Pak=$(command -v apt||echo dnf);
RNDSTR=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n1)");
RNDSTR2=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n1)");
while true; do PORT=$((RANDOM%30000+30000)); nc -z 127.0.0.1 "$PORT" &>/dev/null || break; done
Random_country=$(echo ATBEBGBRCACHCZDEDKEEESFIFRGBHRHUIEINITJPLVNLNOPLPTRORSSESGSKUAUS | fold -w2 | shuf -n1)
TorRandomCountry=$(echo ATBEBGBRCACHCZDEDKEEESFIFRGBHRHUIEINITJPLVNLNOPLPTRORSSESGSKUAUS | fold -w2 | shuf -n1)
##################################Variables###############################################################
XUIDB="/etc/x-ui/x-ui.db";domain="";UNINSTALL="x";PNLNUM=1;CFALLOW="off";NOPATH="";RNDTMPL="n";CLIMIT="#"
WarpCfonCountry="";WarpLicKey="";CleanKeyCfon="";TorCountry="";Secure="no";ENABLEUFW="";VERSION="last";CountryAllow="XX"
################################Get arguments#############################################################
while [ "$#" -gt 0 ]; do
  case "$1" in
  	-country) CountryAllow="$2"; shift 2;;
  	-xuiver) VERSION="$2"; shift 2;;
  	-ufw) ENABLEUFW="$2"; shift 2;;
	-secure) Secure="$2"; shift 2;;
	-TorCountry) TorCountry="$2"; shift 2;;
	-WarpCfonCountry) WarpCfonCountry="$2"; shift 2;;
	-WarpLicKey) WarpLicKey="$2"; shift 2;;
	-CleanKeyCfon) CleanKeyCfon="$2"; shift 2;;
	-RandomTemplate) RNDTMPL="$2"; shift 2;;
	-Uninstall) UNINSTALL="$2"; shift 2;;
	-panel) PNLNUM="$2"; shift 2;;
	-subdomain) domain="$2"; shift 2;;
	-cdn) CFALLOW="$2"; shift 2;;
    *) shift 1;;
  esac
done
#############################################################################################################
service_enable() {
for service_name in "$@"; do
	systemctl is-active --quiet "$service_name" && systemctl stop "$service_name" > /dev/null 2>&1
	systemctl daemon-reload	> /dev/null 2>&1
	systemctl enable "$service_name" > /dev/null 2>&1
	systemctl start "$service_name" > /dev/null 2>&1
done
}

##############################Uninstall##################################################################
if [[ "${UNINSTALL}" == *"y"* ]]; then
	echo "python3-certbot-nginx nginx nginx-full nginx-core nginx-common nginx-extras tor" | xargs -n 1 $Pak -y remove
	for service in nginx tor x-ui warp-plus xray; do
		systemctl stop "$service" > /dev/null 2>&1
		systemctl disable "$service" > /dev/null 2>&1
	done
	#bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
 	rm -rf /etc/warp-plus/ /etc/nginx/sites-enabled/*
	crontab -l | grep -v "nginx\|systemctl\|x-ui" | crontab -	
	command -v x-ui &> /dev/null && printf 'y\n' | x-ui uninstall
	
	clear && msg_ok "Completely Uninstalled!" && exit 1
fi
##############################Domain Validations#########################################################
while [[ -z $(echo "$domain" | tr -d '[:space:]') ]]; do
	read -rp $'\e[1;32;40m Enter available subdomain (sub.domain.tld): \e[0m' domain
done

domain=$(echo "$domain" 2>&1 | tr -d '[:space:]' )
SubDomain=$(echo "$domain" 2>&1 | sed 's/^[^ ]* \|\..*//g')
MainDomain=$(echo "$domain" 2>&1 | sed 's/.*\.\([^.]*\..*\)$/\1/')

if [[ "${SubDomain}.${MainDomain}" != "${domain}" ]] ; then
	MainDomain=${domain}
fi
###############################Install Packages#########################################################
ufw disable
if [[ ${INSTALL} == *"y"* ]]; then

	apt -y update

        apt -y install curl wget jq bash sudo nginx-full certbot python3-certbot-nginx sqlite3 ufw

        systemctl daemon-reload && systemctl enable --now nginx
	
fi
systemctl stop nginx
fuser -k 80/tcp 80/udp 443/tcp 443/udp 2>/dev/null
############################### Get nginx Ver and Stop ##################################################
vercompare() { 
	if [ "$1" = "$2" ]; then echo "E"; return; fi
    [ "$(printf "%s\n%s" "$1" "$2" | sort -V | head -n1)" = "$1" ] && echo "L" || echo "G";
}
nginx_ver=$(nginx -v 2>&1 | awk -F/ '{print $2}');
ver_compare=$(vercompare "$nginx_ver" "1.25.1"); 
if [ "$ver_compare" = "L" ]; then
	 OLD_H2=" http2";NEW_H2="#";
else OLD_H2="";NEW_H2="";
fi
####### Stop nginx
sudo nginx -s stop 2>/dev/null
sudo systemctl stop nginx 2>/dev/null
sudo fuser -k 80/tcp 80/udp 443/tcp 443/udp 2>/dev/null
##################################GET SERVER IPv4-6######################################################
IP4_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
IP6_REGEX="([a-f0-9:]+:+)+[a-f0-9]+"
IP4=$(ip route get 8.8.8.8 2>&1 | grep -Po -- 'src \K\S*')
IP6=$(ip route get 2620:fe::fe 2>&1 | grep -Po -- 'src \K\S*')
[[ $IP4 =~ $IP4_REGEX ]] || IP4=$(curl -s ipv4.icanhazip.com);
[[ $IP6 =~ $IP6_REGEX ]] || IP6=$(curl -s ipv6.icanhazip.com);
##############################Install SSL################################################################
certbot certonly --standalone --non-interactive --force-renewal --agree-tos --register-unsafely-without-email --cert-name "$MainDomain" -d "$domain"
if [[ ! -d "/etc/letsencrypt/live/${MainDomain}/" ]]; then
 	systemctl start nginx >/dev/null 2>&1
	msg_err "$MainDomain SSL failed! Check Domain/IP! Exceeded limit!? Try another domain or VPS!" && exit 1
fi

######################################## add_slashes /webBasePath/ #####################################
add_slashes() {
    [[ "$1" =~ ^/ ]] || set -- "/$1" ; [[ "$1" =~ /$ ]] || set -- "$1/"
    echo "$1"
}
########################################Update X-UI Port/Path for first INSTALL#########################
UPDATE_XUIDB(){
if [[ -f $XUIDB ]]; then
x-ui stop > /dev/null 2>&1
fuser "$XUIDB" 2>/dev/null
RNDSTRSLASH=$(add_slashes "$RNDSTR")
sqlite3 "$XUIDB" << EOF
	DELETE FROM 'settings' WHERE key IN ('webPort', 'webCertFile', 'webKeyFile', 'webBasePath');
	INSERT INTO 'settings' (key, value) VALUES ('webPort', '${PORT}'),('webCertFile', ''),('webKeyFile', ''),('webBasePath', '${RNDSTRSLASH}');
EOF
fi
}
###################################Install X-UI#########################################################
if ! systemctl is-active --quiet x-ui || ! command -v x-ui &> /dev/null; then
	[[ "$PNLNUM" =~ ^[0-3]+$ ]] || PNLNUM=1	
 	VERSION=$(echo "$VERSION" | tr -d '[:space:]')
	if [[ -z "$VERSION" || "$VERSION" != *.* ]]; then VERSION="master"
	else [[ $PNLNUM == "1" ]] && VERSION="v${VERSION#v}" || VERSION="${VERSION#v}" ; fi	
	PANEL=( "https://raw.githubusercontent.com/alireza0/x-ui/${VERSION}/install.sh"
		"https://raw.githubusercontent.com/mhsanaei/3x-ui/${VERSION}/install.sh"
		"https://raw.githubusercontent.com/FranzKafkaYu/x-ui/${VERSION}/install_en.sh"
		"https://raw.githubusercontent.com/AghayeCoder/tx-ui/${VERSION}/install.sh"
	);
	[[ "$VERSION" == "master" ]] && VERSION=""
	printf 'n\n' | bash <(wget -qO- "${PANEL[$PNLNUM]}") "$VERSION" ||  { printf 'n\n' | bash <(curl -Ls "${PANEL[$PNLNUM]}") "$VERSION"; }
	service_enable "x-ui"
 	UPDATE_XUIDB
fi
###################################Get Installed XUI Port/Path##########################################
if [[ -f $XUIDB ]]; then
	x-ui stop > /dev/null 2>&1
 	fuser "$XUIDB" 2>/dev/null
	PORT=$(sqlite3 "${XUIDB}" "SELECT value FROM settings WHERE key='webPort' LIMIT 1;" 2>&1)
 	RNDSTR=$(sqlite3 "${XUIDB}" "SELECT value FROM settings WHERE key='webBasePath' LIMIT 1;" 2>&1)	
	XUIUSER=$(sqlite3 "${XUIDB}" 'SELECT "username" FROM users;' 2>&1)
	XUIPASS=$(sqlite3 "${XUIDB}" 'SELECT "password" FROM users;' 2>&1)
	RNDSTR=$(add_slashes "$RNDSTR" | tr -d '[:space:]')
	[[ "$RNDSTR" == "/" ]] && NOPATH="#"
	if [[ -z "${PORT}" ]] || ! [[ "${PORT}" =~ ^-?[0-9]+$ ]]; then
		PORT="2053"
  	fi
else
	PORT="2053"
	RNDSTR="/";NOPATH="#";
	XUIUSER="admin";XUIPASS="admin";
fi
#######################################################################################################
CountryAllow=$(echo "$CountryAllow" | tr ',' '|' | tr -cd 'A-Za-z|' | awk '{print toupper($0)}')
if echo "$CountryAllow" | grep -Eq '^[A-Z]{2}(\|[A-Z]{2})*$'; then
	CLIMIT=$( [[ "$CountryAllow" == "XX" ]] && echo "#" || echo "" )
fi
#################################Nginx Config###########################################################
cat > "/etc/nginx/sites-available/$MainDomain" << EOF
server {
	server_tokens off;
	server_name $MainDomain *.$MainDomain;
	listen 80;
	listen [::]:80;
	listen 443 ssl${OLD_H2};
	listen [::]:443 ssl${OLD_H2};
	${NEW_H2}http2 on; http3 on;
	index index.html index.htm index.php index.nginx-debian.html;
	root /var/www/html/;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
	ssl_certificate /etc/letsencrypt/live/$MainDomain/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/$MainDomain/privkey.pem;
	if (\$host !~* ^(.+\.)?$MainDomain\$ ){return 444;}
	if (\$scheme ~* https) {set \$safe 1;}
	if (\$ssl_server_name !~* ^(.+\.)?$MainDomain\$ ) {set \$safe "\${safe}0"; }
	if (\$safe = 10){return 444;}
	if (\$request_uri ~ "(\"|'|\`|~|,|:|--|;|%|\\$|&&|\?\?|0x00|0X00|\||\\|\{|\}|\[|\]|<|>|\.\.\.|\.\.\/|\/\/\/)"){set \$hack 1;}
	error_page 400 402 403 500 501 502 503 504 =404 /404;
	proxy_intercept_errors on;
	#X-UI Admin Panel
	location $RNDSTR {
		${Secure}auth_basic "Restricted Access";
		${Secure}auth_basic_user_file /etc/nginx/.htpasswd;
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:$PORT;
		break;
	}
	#Subscription Path (simple/encode)
	location ~ ^/(?<fwdport>\d+)/sub/(?<fwdpath>.*)\$ {
		if (\$hack = 1) {return 404;}
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:\$fwdport/sub/\$fwdpath\$is_args\$args;
		break;
	}
	#Subscription Path (json/fragment)
	location ~ ^/(?<fwdport>\d+)/json/(?<fwdpath>.*)\$ {
		if (\$hack = 1) {return 404;}
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:\$fwdport/json/\$fwdpath\$is_args\$args;
		break;
	}
	#Xray Config Path
	location ~ ^/(?<fwdport>\d+)/(?<fwdpath>.*)\$ {
		if (\$hack = 1) {return 404;}
		${CF_IP}if (\$cloudflare_ip != 1) {return 404;}
		${CLIMIT}if (\$http_cf_ipcountry !~* "${CountryAllow}"){ return 404; }
		${Secure}if (\$http_user_agent ~* "(bot|clash|fair|go-http|hiddify|java|neko|node|proxy|python|ray|sager|sing|tunnel|v2box|vpn)") { return 404; }
		client_max_body_size 0;
		client_body_timeout 1d;
		grpc_read_timeout 1d;
		grpc_socket_keepalive on;
		proxy_read_timeout 1d;
		proxy_http_version 1.1;
		proxy_buffering off;
		proxy_request_buffering off;
		proxy_socket_keepalive on;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		if (\$content_type ~* "GRPC") { grpc_pass grpc://127.0.0.1:\$fwdport\$is_args\$args; break; }
		proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
		break;
	}
	$NOPATH location / { try_files \$uri \$uri/ =404; }
}
EOF
if [[ -f "/etc/nginx/sites-available/$MainDomain" ]]; then
	unlink "/etc/nginx/sites-enabled/default" >/dev/null 2>&1
	rm -f "/etc/nginx/sites-enabled/default" "/etc/nginx/sites-available/default"
	ln -fs "/etc/nginx/sites-available/$MainDomain" "/etc/nginx/sites-enabled/" 2>/dev/null
fi
sudo rm -f /etc/nginx/sites-enabled/*{~,bak,backup,save,swp,tmp}
##################################Check Nginx status####################################################
if ! systemctl start nginx > /dev/null 2>&1 || ! nginx -t &>/dev/null || nginx -s reload 2>&1 | grep -q error; then
	pkill -9 nginx || killall -9 nginx
	nginx -c /etc/nginx/nginx.conf
	nginx -s reload
fi
systemctl is-enabled x-ui || sudo systemctl enable x-ui
x-ui start > /dev/null 2>&1

######################cronjob for ssl/reload service/cloudflareips######################################
tasks=(
  "0 0 * * * sudo su -c 'x-ui restart > /dev/null 2>&1 '"
  "0 0 * * * sudo su -c 'nginx -s reload 2>&1 | grep -q error && { pkill nginx || killall nginx; nginx -c /etc/nginx/nginx.conf; nginx -s reload; }'"
  "0 0 1 * * sudo su -c 'certbot renew --nginx --force-renewal --non-interactive --post-hook \"nginx -s reload\" > /dev/null 2>&1'"
)
crontab -l | grep -qE "x-ui" || { printf "%s\n" "${tasks[@]}" | crontab -; }
####################################UFW Rules################################################################
ufw disable
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
##################################Show Details##########################################################
if systemctl is-active --quiet x-ui || command -v x-ui &> /dev/null; then 
	printf '0\n' | x-ui | grep --color=never -i ':' | awk '{print "\033[1;37;40m" $0 "\033[0m"}'
	hrline
 	nginx -T | grep -i 'configuration file /etc/nginx/sites-enabled/'  | sed 's/.*configuration file //'  | tr -d ':' | awk '{print "\033[1;32;40m" $0 "\033[0m"}'
	hrline
	certbot certificates | grep -i 'Path:\|Domains:\|Expiry Date:' | awk '{print "\033[1;37;40m" $0 "\033[0m"}'
	hrline
	IPInfo=$(curl -Ls "https://ipapi.co/json" || curl -Ls "https://ipinfo.io/json")
 	OS=$(grep -E '^(NAME|VERSION)=' /etc/*release 2>/dev/null | awk -F= '{printf $2 " "}' | xargs)
	msg "ID: $(cat /etc/machine-id | cksum | awk '{print $1 % 65536}') | IP: ${IP4} | OS: ${OS}"
	msg "Hostname: $(uname -n) | $(echo "${IPInfo}" | jq -r '.org, .country' | paste -sd' | ')"
 	printf "\033[1;37;40m CPU: %s/%s Core | RAM: %s | SSD: %s Gi\033[0m\n" \
	"$(arch)" "$(nproc)" "$(free -h | awk '/^Mem:/{print $2}')" "$(df / | awk 'NR==2 {print $2 / 1024 / 1024}')"
	hrline
  	msg_err  "XrayUI Panel [IP:PORT/PATH]"
	[[ -n "$IP4" && "$IP4" =~ $IP4_REGEX ]] && msg_inf "IPv4: http://$IP4:$PORT$RNDSTR"
	[[ -n "$IP6" && "$IP6" =~ $IP6_REGEX ]] && msg_inf "IPv6: http://[$IP6]:$PORT$RNDSTR"
	hrline
	sudo sh -c "echo -n '${XUIUSER}:' >> /etc/nginx/.htpasswd && openssl passwd -apr1 '${XUIPASS}' >> /etc/nginx/.htpasswd"
 	msg_ok "Admin Panel [SSL]:\n"
	msg_inf "XrayUI: https://${domain}${RNDSTR}"
	msg "Username: $XUIUSER\n Password: $XUIPASS"
	hrline
	msg_war "Note: Save This Screen!"	
else
	nginx -t && printf '0\n' | x-ui | grep --color=never -i ':'
	msg_err "XUI-PRO : Installation error..."
fi
################################################ N-joy #################################################
