#!/bin/bash

# ============================================
# CloudFlare Origin SSL - Instalação Manual
# GitHub: artificialsynapse/instalar-ssl
# Uso: ./cf-ssl-manual.sh dominio.com
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

# Banner
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   CloudFlare Origin SSL - Manual      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"

# Validar root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ Execute como root: sudo $0 $@${NC}"
   exit 1
fi

# Validar domínio
if [[ -z "$DOMAIN" ]]; then
    echo -e "${YELLOW}Digite o domínio (ex: exemplo.com):${NC}"
    read -r DOMAIN
fi

echo -e "${GREEN}📌 Domínio: $DOMAIN${NC}"
echo ""

# Instalar dependências
echo -e "${YELLOW}📦 Instalando dependências...${NC}"
apt-get update -qq
apt-get install -y nginx > /dev/null 2>&1
echo -e "${GREEN}✅ Nginx instalado${NC}"

# Criar diretório para certificados
mkdir -p /etc/ssl/cloudflare

# Instruções para obter certificado
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════${NC}"
echo -e "${YELLOW}📋 INSTRUÇÕES PARA OBTER O CERTIFICADO:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}1. Acesse sua conta CloudFlare:${NC}"
echo "   https://dash.cloudflare.com"
echo ""
echo -e "${BLUE}2. Selecione o domínio:${NC}"
echo "   $DOMAIN"
echo ""
echo -e "${BLUE}3. No menu lateral, vá em:${NC}"
echo "   SSL/TLS → Origin Server"
echo ""
echo -e "${BLUE}4. Clique em:${NC}"
echo "   'Create Certificate'"
echo ""
echo -e "${BLUE}5. Configure:${NC}"
echo "   • Hostnames: $DOMAIN e *.$DOMAIN"
echo "   • Validity: 15 years"
echo "   • Key Format: PEM (padrão)"
echo ""
echo -e "${BLUE}6. Clique em 'Create'${NC}"
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════${NC}"
echo ""

# Pedir certificado
echo -e "${GREEN}📝 PASSO 1: Cole o Origin Certificate${NC}"
echo -e "${YELLOW}(Copie TODO o conteúdo, incluindo as linhas BEGIN e END)${NC}"
echo -e "${YELLOW}Quando terminar de colar, pressione ENTER e depois CTRL+D:${NC}"
echo ""

# Criar arquivo temporário para ler o certificado
TEMP_CERT=$(mktemp)
cat > "$TEMP_CERT"

# Verificar se o certificado foi colado
if [ ! -s "$TEMP_CERT" ]; then
    echo -e "${RED}❌ Nenhum certificado foi colado${NC}"
    rm -f "$TEMP_CERT"
    exit 1
fi

# Verificar se é um certificado válido
if grep -q "BEGIN CERTIFICATE" "$TEMP_CERT" && grep -q "END CERTIFICATE" "$TEMP_CERT"; then
    mv "$TEMP_CERT" "/etc/ssl/cloudflare/$DOMAIN.pem"
    chmod 644 "/etc/ssl/cloudflare/$DOMAIN.pem"
    echo -e "${GREEN}✅ Certificado salvo${NC}"
else
    echo -e "${RED}❌ Certificado inválido. Certifique-se de copiar todo o conteúdo${NC}"
    rm -f "$TEMP_CERT"
    exit 1
fi

echo ""
echo -e "${GREEN}📝 PASSO 2: Cole a Private Key${NC}"
echo -e "${YELLOW}(Copie TODO o conteúdo, incluindo as linhas BEGIN e END)${NC}"
echo -e "${YELLOW}Quando terminar de colar, pressione ENTER e depois CTRL+D:${NC}"
echo ""

# Criar arquivo temporário para ler a chave
TEMP_KEY=$(mktemp)
cat > "$TEMP_KEY"

# Verificar se a chave foi colada
if [ ! -s "$TEMP_KEY" ]; then
    echo -e "${RED}❌ Nenhuma chave foi colada${NC}"
    rm -f "$TEMP_KEY"
    exit 1
fi

# Verificar se é uma chave válida
if grep -q "BEGIN.*PRIVATE KEY" "$TEMP_KEY" && grep -q "END.*PRIVATE KEY" "$TEMP_KEY"; then
    mv "$TEMP_KEY" "/etc/ssl/cloudflare/$DOMAIN.key"
    chmod 600 "/etc/ssl/cloudflare/$DOMAIN.key"
    echo -e "${GREEN}✅ Chave privada salva${NC}"
else
    echo -e "${RED}❌ Chave inválida. Certifique-se de copiar todo o conteúdo${NC}"
    rm -f "$TEMP_KEY"
    exit 1
fi

# Configurar Nginx
echo ""
echo -e "${YELLOW}⚙️  Configurando Nginx...${NC}"

cat > /etc/nginx/sites-available/$DOMAIN << NGINX_CONFIG
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
    
    # SSL CloudFlare Origin
    ssl_certificate /etc/ssl/cloudflare/$DOMAIN.pem;
    ssl_certificate_key /etc/ssl/cloudflare/$DOMAIN.key;
    
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
    
    # CloudFlare Real IPs
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
    
    # Gzip
    gzip on;
    gzip_vary on;
    gzip_min_length 1000;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss;
    
    # Negar arquivos ocultos
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
}
NGINX_CONFIG

# Ativar site
ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Testar configuração
if nginx -t > /dev/null 2>&1; then
    systemctl reload nginx
    echo -e "${GREEN}✅ Nginx configurado com sucesso${NC}"
else
    echo -e "${RED}❌ Erro na configuração do Nginx${NC}"
    nginx -t
    exit 1
fi

# Verificações finais
echo ""
echo -e "${YELLOW}🧪 Verificando instalação...${NC}"

# Verificar certificados
if [ -f "/etc/ssl/cloudflare/$DOMAIN.pem" ] && [ -f "/etc/ssl/cloudflare/$DOMAIN.key" ]; then
    echo -e "${GREEN}✅ Certificados instalados${NC}"
else
    echo -e "${RED}❌ Certificados não encontrados${NC}"
fi

# Verificar Nginx
if systemctl is-active --quiet nginx; then
    echo -e "${GREEN}✅ Nginx está rodando${NC}"
else
    echo -e "${RED}❌ Nginx não está rodando${NC}"
fi

# Testar HTTPS local
if timeout 2 curl -ksI https://localhost > /dev/null 2>&1; then
    echo -e "${GREEN}✅ HTTPS respondendo${NC}"
else
    echo -e "${YELLOW}⚠️  HTTPS pode levar alguns segundos para iniciar${NC}"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✅ SSL CONFIGURADO COM SUCESSO!     ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}🌐 Seu site está disponível em:${NC}"
echo -e "${GREEN}   https://$DOMAIN${NC}"
echo -e "${GREEN}   https://www.$DOMAIN${NC}"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANTE - Configure no CloudFlare:${NC}"
echo ""
echo "1. ${BLUE}SSL/TLS → Overview${NC}"
echo "   Selecione: ${GREEN}Full (Strict)${NC}"
echo ""
echo "2. ${BLUE}SSL/TLS → Edge Certificates${NC}"
echo "   Ative: ${GREEN}Always Use HTTPS${NC}"
echo "   Ative: ${GREEN}Automatic HTTPS Rewrites${NC}"
echo ""
echo -e "${YELLOW}📁 Arquivos:${NC}"
echo "• Certificado: /etc/ssl/cloudflare/$DOMAIN.pem"
echo "• Chave: /etc/ssl/cloudflare/$DOMAIN.key"
echo "• Config Nginx: /etc/nginx/sites-available/$DOMAIN"
echo ""
echo -e "${GREEN}✨ Pronto! Certificado válido por 15 anos!${NC}"
