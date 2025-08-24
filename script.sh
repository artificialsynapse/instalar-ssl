#!/bin/bash

# ============================================
# Script Simplificado SSL - Let's Encrypt Auto
# GitHub: artificialsynapse/instalar-ssl
# Uso: ./ssl-auto.sh dominio.com [email]
# ============================================

set -e

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Validar argumentos
DOMAIN=${1:-""}
EMAIL=${2:-"admin@$DOMAIN"}

# Banner
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   SSL Let's Encrypt - Auto Install    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"

# Validar root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ Execute como root: sudo $0 $@${NC}"
   exit 1
fi

# Validar domínio
if [[ -z "$DOMAIN" ]]; then
    echo -e "${RED}❌ Uso: $0 dominio.com [email]${NC}"
    echo -e "${YELLOW}Exemplo: $0 exemplo.com admin@exemplo.com${NC}"
    exit 1
fi

echo -e "${GREEN}📌 Domínio: $DOMAIN${NC}"
echo -e "${GREEN}📌 Email: $EMAIL${NC}"
echo ""

# Instalar dependências
echo -e "${YELLOW}📦 Instalando dependências...${NC}"
apt-get update -qq
apt-get install -y nginx certbot python3-certbot-nginx > /dev/null 2>&1
echo -e "${GREEN}✅ Dependências instaladas${NC}"

# Criar configuração Nginx básica
echo -e "${YELLOW}⚙️  Configurando Nginx...${NC}"

cat > /etc/nginx/sites-available/$DOMAIN << 'NGINX'
server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_PLACEHOLDER www.DOMAIN_PLACEHOLDER;
    
    root /var/www/html;
    index index.php index.html index.htm;
    
    # CloudFlare Real IP
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 173.245.48.0/20;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~* \.(jpg|jpeg|gif|png|webp|svg|woff|woff2|ttf|css|js|ico|xml)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    location ~ /\. {
        deny all;
    }
}
NGINX

# Substituir placeholder
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" /etc/nginx/sites-available/$DOMAIN

# Ativar site
ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Testar e recarregar Nginx
nginx -t > /dev/null 2>&1
systemctl reload nginx
echo -e "${GREEN}✅ Nginx configurado${NC}"

# Obter certificado Let's Encrypt
echo -e "${YELLOW}🔐 Obtendo certificado SSL...${NC}"

# Parar Nginx temporariamente para validação
systemctl stop nginx

# Tentar obter certificado
certbot certonly --standalone \
    -d $DOMAIN \
    -d www.$DOMAIN \
    --non-interactive \
    --agree-tos \
    --email $EMAIL \
    --no-eff-email

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Certificado SSL obtido${NC}"
else
    echo -e "${RED}❌ Erro ao obter certificado${NC}"
    echo -e "${YELLOW}Tentando método alternativo...${NC}"
    
    # Reiniciar Nginx e tentar com webroot
    systemctl start nginx
    certbot --nginx \
        -d $DOMAIN \
        -d www.$DOMAIN \
        --non-interactive \
        --agree-tos \
        --email $EMAIL \
        --no-eff-email
        
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Falha ao obter certificado SSL${NC}"
        echo -e "${YELLOW}Verifique se o domínio aponta para este servidor${NC}"
        exit 1
    fi
fi

# Configurar Nginx com SSL
echo -e "${YELLOW}🔧 Configurando SSL no Nginx...${NC}"

cat > /etc/nginx/sites-available/$DOMAIN << NGINX_SSL
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN www.$DOMAIN;
    
    root /var/www/html;
    index index.php index.html index.htm;
    
    # SSL Let's Encrypt
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    # SSL Configurações
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # CloudFlare Real IP
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 173.245.48.0/20;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    
    # Logs
    access_log /var/log/nginx/$DOMAIN.access.log;
    error_log /var/log/nginx/$DOMAIN.error.log;
    
    # PHP
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Cache de arquivos estáticos
    location ~* \.(jpg|jpeg|gif|png|webp|svg|woff|woff2|ttf|css|js|ico|xml)$ {
        expires 365d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    
    # Negar arquivos ocultos
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Try files
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
}
NGINX_SSL

# Reiniciar Nginx
systemctl start nginx
nginx -t > /dev/null 2>&1
systemctl reload nginx

# Configurar renovação automática
echo -e "${YELLOW}⏰ Configurando renovação automática...${NC}"
(crontab -l 2>/dev/null; echo "0 0,12 * * * certbot renew --quiet --no-self-upgrade --post-hook 'systemctl reload nginx'") | crontab -
echo -e "${GREEN}✅ Renovação automática configurada${NC}"

# Teste final
echo ""
echo -e "${YELLOW}🧪 Testando configuração...${NC}"

# Verificar se Nginx está rodando
if systemctl is-active --quiet nginx; then
    echo -e "${GREEN}✅ Nginx está rodando${NC}"
else
    echo -e "${RED}❌ Nginx não está rodando${NC}"
fi

# Verificar certificado
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo -e "${GREEN}✅ Certificado SSL encontrado${NC}"
else
    echo -e "${RED}❌ Certificado SSL não encontrado${NC}"
fi

# Teste HTTPS local
if curl -ksI https://localhost | grep -q "200\|301\|302" 2>/dev/null; then
    echo -e "${GREEN}✅ HTTPS respondendo localmente${NC}"
else
    echo -e "${YELLOW}⚠️  HTTPS não responde localmente ainda${NC}"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    ✅ SSL INSTALADO COM SUCESSO!      ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}🌐 Seu site está disponível em:${NC}"
echo -e "${GREEN}   https://$DOMAIN${NC}"
echo -e "${GREEN}   https://www.$DOMAIN${NC}"
echo ""
echo -e "${YELLOW}📝 Informações importantes:${NC}"
echo "• Certificado válido por 90 dias"
echo "• Renovação automática configurada"
echo "• Logs em: /var/log/nginx/$DOMAIN.*.log"
echo "• Config em: /etc/nginx/sites-available/$DOMAIN"
echo ""

# Verificar se usa CloudFlare
if curl -sI "http://$DOMAIN" 2>/dev/null | grep -qi "cloudflare"; then
    echo -e "${YELLOW}☁️  CloudFlare detectado!${NC}"
    echo "• Configure SSL/TLS → Full (Strict)"
    echo "• Ative 'Always Use HTTPS'"
    echo ""
fi

echo -e "${GREEN}✨ Pronto! SSL configurado e funcionando!${NC}"
