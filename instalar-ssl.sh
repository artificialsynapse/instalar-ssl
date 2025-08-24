#!/bin/bash

# Script Automatizado de Instalação SSL
# Uso: ./instalar-ssl.sh dominio.com [email]

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Variáveis
DOMAIN=${1:-""}
EMAIL=${2:-"admin@$DOMAIN"}
NGINX_CONF="/etc/nginx/sites-available/default"
SSL_DIR="/etc/ssl"

# Banner
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}     INSTALADOR AUTOMÁTICO DE SSL${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

# Função para verificar se é root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Este script precisa ser executado como root${NC}"
        echo "Use: sudo $0 $@"
        exit 1
    fi
}

# Função para validar domínio
validate_domain() {
    if [[ -z "$DOMAIN" ]]; then
        echo -e "${YELLOW}Digite o domínio (ex: exemplo.com):${NC}"
        read DOMAIN
    fi
    
    # Validação básica do formato
    if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}Domínio inválido! Use formato: exemplo.com${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Domínio: $DOMAIN${NC}"
}

# Função para detectar CloudFlare
detect_cloudflare() {
    echo -e "${YELLOW}Verificando se o domínio usa CloudFlare...${NC}"
    
    # Verifica nameservers
    if nslookup -type=ns $DOMAIN 2>/dev/null | grep -q "cloudflare.com"; then
        echo -e "${GREEN}✓ CloudFlare detectado!${NC}"
        return 0
    else
        echo -e "${YELLOW}CloudFlare não detectado ou domínio não propagado ainda${NC}"
        return 1
    fi
}

# Função para instalar CloudFlare Origin Certificate
install_cloudflare_origin() {
    echo -e "${GREEN}=== Instalando CloudFlare Origin Certificate ===${NC}"
    echo ""
    echo -e "${YELLOW}Passos no painel CloudFlare:${NC}"
    echo "1. Acesse: SSL/TLS → Origin Server"
    echo "2. Clique em 'Create Certificate'"
    echo "3. Adicione: $DOMAIN e *.$DOMAIN"
    echo "4. Escolha: 15 anos de validade"
    echo "5. Copie o certificado e a chave"
    echo ""
    echo -e "${YELLOW}Cole o CERTIFICADO abaixo (termine com ENTER + CTRL+D):${NC}"
    
    # Criar diretório se não existir
    mkdir -p $SSL_DIR/cloudflare
    
    # Ler certificado
    cat > $SSL_DIR/cloudflare/$DOMAIN.pem
    
    echo -e "${YELLOW}Cole a CHAVE PRIVADA abaixo (termine com ENTER + CTRL+D):${NC}"
    
    # Ler chave privada
    cat > $SSL_DIR/cloudflare/$DOMAIN.key
    
    # Ajustar permissões
    chmod 600 $SSL_DIR/cloudflare/$DOMAIN.key
    
    # Configurar Nginx
    configure_nginx_ssl "$SSL_DIR/cloudflare/$DOMAIN.pem" "$SSL_DIR/cloudflare/$DOMAIN.key"
    
    echo -e "${GREEN}✓ CloudFlare Origin Certificate instalado!${NC}"
    echo -e "${YELLOW}IMPORTANTE: Configure no CloudFlare: SSL/TLS → Full (Strict)${NC}"
}

# Função para instalar Let's Encrypt
install_letsencrypt() {
    echo -e "${GREEN}=== Instalando Let's Encrypt ===${NC}"
    
    # Instalar Certbot se necessário
    if ! command -v certbot &> /dev/null; then
        echo "Instalando Certbot..."
        apt-get update
        apt-get install -y certbot python3-certbot-nginx
    fi
    
    # Parar Nginx temporariamente para validação
    echo "Configurando certificado..."
    
    # Tentar com Nginx plugin primeiro (não precisa parar o serviço)
    if certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos --email $EMAIL; then
        echo -e "${GREEN}✓ Let's Encrypt instalado com sucesso!${NC}"
    else
        echo -e "${YELLOW}Tentando método alternativo...${NC}"
        # Se falhar, tentar standalone
        systemctl stop nginx
        if certbot certonly --standalone -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos --email $EMAIL; then
            systemctl start nginx
            configure_nginx_ssl "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
            echo -e "${GREEN}✓ Let's Encrypt instalado via standalone!${NC}"
        else
            systemctl start nginx
            echo -e "${RED}Erro ao instalar Let's Encrypt${NC}"
            return 1
        fi
    fi
    
    # Configurar renovação automática
    echo "0 0,12 * * * root python3 -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew -q" | tee -a /etc/crontab > /dev/null
    
    echo -e "${GREEN}✓ Renovação automática configurada${NC}"
}

# Função para instalar certificado auto-assinado
install_selfsigned() {
    echo -e "${GREEN}=== Instalando Certificado Auto-Assinado ===${NC}"
    
    mkdir -p $SSL_DIR/selfsigned
    
    # Gerar certificado
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout $SSL_DIR/selfsigned/$DOMAIN.key \
        -out $SSL_DIR/selfsigned/$DOMAIN.crt \
        -subj "/C=BR/ST=SP/L=SaoPaulo/O=Company/CN=$DOMAIN"
    
    # Ajustar permissões
    chmod 600 $SSL_DIR/selfsigned/$DOMAIN.key
    
    # Configurar Nginx
    configure_nginx_ssl "$SSL_DIR/selfsigned/$DOMAIN.crt" "$SSL_DIR/selfsigned/$DOMAIN.key"
    
    echo -e "${GREEN}✓ Certificado auto-assinado instalado!${NC}"
    echo -e "${YELLOW}Nota: Use CloudFlare no modo 'Full' (não 'Full Strict')${NC}"
}

# Função para configurar Nginx com SSL
configure_nginx_ssl() {
    local CERT_PATH=$1
    local KEY_PATH=$2
    
    echo "Configurando Nginx..."
    
    # Backup da configuração atual
    cp $NGINX_CONF ${NGINX_CONF}.backup.$(date +%Y%m%d-%H%M%S)
    
    # Criar nova configuração
    cat > $NGINX_CONF << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;
    
    # Redirect HTTP to HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    server_name $DOMAIN www.$DOMAIN;
    root /var/www/html;
    index index.php index.html index.htm;
    
    # SSL Configuration
    ssl_certificate $CERT_PATH;
    ssl_certificate_key $KEY_PATH;
    
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
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 173.245.48.0/20;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    
    # Compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1000;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss;
    
    # Locations
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~* \.(jpg|jpeg|gif|png|webp|svg|woff|woff2|ttf|css|js|ico|xml)$ {
        expires 365d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    
    location ~ /\\.(?!well-known) {
        deny all;
    }
}
EOF
    
    # Testar configuração
    if nginx -t; then
        systemctl reload nginx
        echo -e "${GREEN}✓ Nginx configurado com SSL!${NC}"
    else
        echo -e "${RED}Erro na configuração do Nginx!${NC}"
        echo "Restaurando backup..."
        mv ${NGINX_CONF}.backup.$(date +%Y%m%d-%H%M%S) $NGINX_CONF
        systemctl reload nginx
        exit 1
    fi
}

# Função para escolha automática
auto_install() {
    if detect_cloudflare; then
        echo -e "${YELLOW}CloudFlare detectado! Recomendamos CloudFlare Origin Certificate.${NC}"
        echo "Escolha o método:"
        echo "1) CloudFlare Origin Certificate (Recomendado)"
        echo "2) Let's Encrypt"
        echo "3) Auto-assinado"
    else
        echo -e "${YELLOW}CloudFlare não detectado. Recomendamos Let's Encrypt.${NC}"
        echo "Escolha o método:"
        echo "1) Let's Encrypt (Recomendado)"
        echo "2) CloudFlare Origin Certificate"
        echo "3) Auto-assinado"
    fi
    
    read -p "Opção [1]: " choice
    choice=${choice:-1}
    
    case $choice in
        1)
            if detect_cloudflare; then
                install_cloudflare_origin
            else
                install_letsencrypt
            fi
            ;;
        2)
            if detect_cloudflare; then
                install_letsencrypt
            else
                install_cloudflare_origin
            fi
            ;;
        3)
            install_selfsigned
            ;;
        *)
            echo -e "${RED}Opção inválida!${NC}"
            exit 1
            ;;
    esac
}

# Função para testar SSL
test_ssl() {
    echo ""
    echo -e "${YELLOW}Testando SSL...${NC}"
    
    # Teste local
    if curl -ksI https://localhost | grep -q "200\|301\|302"; then
        echo -e "${GREEN}✓ SSL funcionando localmente${NC}"
    else
        echo -e "${RED}✗ Problema com SSL local${NC}"
    fi
    
    # Teste externo
    if curl -sI https://$DOMAIN 2>/dev/null | grep -q "200\|301\|302"; then
        echo -e "${GREEN}✓ SSL funcionando externamente${NC}"
    else
        echo -e "${YELLOW}! SSL externo ainda não acessível (DNS pode estar propagando)${NC}"
    fi
}

# Função principal
main() {
    check_root
    validate_domain
    
    echo ""
    echo -e "${GREEN}Domínio: $DOMAIN${NC}"
    echo -e "${GREEN}Email: $EMAIL${NC}"
    echo ""
    
    auto_install
    test_ssl
    
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}     SSL INSTALADO COM SUCESSO!${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    echo -e "${YELLOW}Próximos passos:${NC}"
    echo "1. Teste o site: https://$DOMAIN"
    
    if detect_cloudflare; then
        echo "2. No CloudFlare, configure: SSL/TLS → Full (Strict)"
        echo "3. Ative: Always Use HTTPS"
    fi
    
    echo ""
    echo -e "${GREEN}Configuração salva em: $NGINX_CONF${NC}"
    echo -e "${GREEN}Backups em: ${NGINX_CONF}.backup.*${NC}"
}

# Executar
main