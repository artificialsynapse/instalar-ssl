#!/bin/bash

# ============================================
# Script Universal de SSL + Nginx
# GitHub: seu-usuario/ec2-ssl-setup
# Uso: ./setup-ssl.sh dominio.com [email]
# ============================================

set -e

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variáveis globais
DOMAIN=""
EMAIL=""
WWW_DOMAIN=""
SSL_METHOD=""
NGINX_CONF="/etc/nginx/sites-available"
NGINX_ENABLED="/etc/nginx/sites-enabled"

# Função de ajuda
show_help() {
    echo "Uso: $0 [OPÇÕES]"
    echo ""
    echo "OPÇÕES:"
    echo "  -d, --domain DOMINIO    Domínio para configurar (obrigatório)"
    echo "  -e, --email EMAIL       Email para SSL (opcional)"
    echo "  -m, --method METODO     Método SSL: letsencrypt, cloudflare, selfsigned (padrão: auto)"
    echo "  -h, --help              Mostrar esta ajuda"
    echo ""
    echo "EXEMPLOS:"
    echo "  $0 -d exemplo.com"
    echo "  $0 -d exemplo.com -e admin@exemplo.com -m letsencrypt"
    echo "  $0 --domain exemplo.com --method cloudflare"
}

# Processar argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -e|--email)
            EMAIL="$2"
            shift 2
            ;;
        -m|--method)
            SSL_METHOD="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            # Se não tem flag, assume que é o domínio
            if [[ -z "$DOMAIN" ]]; then
                DOMAIN="$1"
            fi
            shift
            ;;
    esac
done

# Validar root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ Este script precisa ser executado como root${NC}"
   echo "Use: sudo $0 $@"
   exit 1
fi

# Validar domínio
if [[ -z "$DOMAIN" ]]; then
    echo -e "${YELLOW}Digite o domínio (ex: exemplo.com):${NC}"
    read -r DOMAIN
fi

if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
    echo -e "${RED}❌ Domínio inválido: $DOMAIN${NC}"
    exit 1
fi

# Configurar email padrão
if [[ -z "$EMAIL" ]]; then
    EMAIL="admin@$DOMAIN"
fi

# Configurar www
WWW_DOMAIN="www.$DOMAIN"

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Configurador SSL + Nginx          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo -e "${GREEN}📌 Domínio: $DOMAIN${NC}"
echo -e "${GREEN}📌 Email: $EMAIL${NC}"
echo ""

# Função para instalar dependências
install_dependencies() {
    echo -e "${YELLOW}📦 Instalando dependências...${NC}"
    apt-get update -qq
    apt-get install -y nginx certbot python3-certbot-nginx openssl curl > /dev/null 2>&1
    echo -e "${GREEN}✅ Dependências instaladas${NC}"
}

# Função para detectar CloudFlare
detect_cloudflare() {
    echo -e "${YELLOW}🔍 Verificando CloudFlare...${NC}"
    
    # Verificar por headers CloudFlare
    if curl -sI "http://$DOMAIN" 2>/dev/null | grep -qi "cloudflare"; then
        echo -e "${GREEN}✅ CloudFlare detectado${NC}"
        return 0
    fi
    
    # Verificar nameservers
    if host -t ns "$DOMAIN" 2>/dev/null | grep -qi "cloudflare"; then
        echo -e "${GREEN}✅ CloudFlare detectado via NS${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}ℹ️  CloudFlare não detectado${NC}"
    return 1
}

# Função para criar configuração base do Nginx
create_nginx_base() {
    local CONFIG_FILE="$NGINX_CONF/$DOMAIN"
    
    echo -e "${YELLOW}⚙️  Criando configuração Nginx base...${NC}"
    
    cat > "$CONFIG_FILE" << 'NGINX_BASE'
server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_PLACEHOLDER WWW_DOMAIN_PLACEHOLDER;
    
    root /var/www/html;
    index index.php index.html index.htm;
    
    # Logs
    access_log /var/log/nginx/DOMAIN_PLACEHOLDER.access.log;
    error_log /var/log/nginx/DOMAIN_PLACEHOLDER.error.log;
    
    # Security
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # CloudFlare Real IP
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    
    # PHP
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Static files
    location ~* \.(jpg|jpeg|gif|png|webp|svg|woff|woff2|ttf|css|js|ico|xml)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Deny hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
}
NGINX_BASE
    
    # Substituir placeholders
    sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" "$CONFIG_FILE"
    sed -i "s/WWW_DOMAIN_PLACEHOLDER/$WWW_DOMAIN/g" "$CONFIG_FILE"
    
    # Ativar site
    ln -sf "$CONFIG_FILE" "$NGINX_ENABLED/$DOMAIN"
    
    # Remover default se existir
    rm -f "$NGINX_ENABLED/default"
    
    # Testar configuração
    if nginx -t > /dev/null 2>&1; then
        systemctl reload nginx
        echo -e "${GREEN}✅ Configuração Nginx criada${NC}"
        return 0
    else
        echo -e "${RED}❌ Erro na configuração Nginx${NC}"
        return 1
    fi
}

# Função para Let's Encrypt
setup_letsencrypt() {
    echo -e "${BLUE}🔐 Configurando Let's Encrypt...${NC}"
    
    # Parar nginx temporariamente se necessário
    systemctl stop nginx
    
    # Tentar obter certificado
    if certbot certonly --standalone \
        -d "$DOMAIN" \
        -d "$WWW_DOMAIN" \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --no-eff-email; then
        
        echo -e "${GREEN}✅ Certificado Let's Encrypt obtido${NC}"
        
        # Atualizar configuração Nginx
        cat > "$NGINX_CONF/$DOMAIN" << NGINX_SSL
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN $WWW_DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN $WWW_DOMAIN;
    
    root /var/www/html;
    index index.php index.html index.htm;
    
    # SSL
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
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
    }
    
    # Static files cache
    location ~* \.(jpg|jpeg|gif|png|webp|svg|woff|woff2|ttf|css|js|ico|xml)$ {
        expires 365d;
        add_header Cache-Control "public, immutable";
    }
    
    location ~ /\. {
        deny all;
    }
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
}
NGINX_SSL
        
        # Configurar renovação automática
        echo "0 0,12 * * * root certbot renew --quiet --no-self-upgrade --post-hook 'systemctl reload nginx'" >> /etc/crontab
        
        systemctl start nginx
        systemctl reload nginx
        
        return 0
    else
        echo -e "${RED}❌ Falha ao obter certificado Let's Encrypt${NC}"
        systemctl start nginx
        return 1
    fi
}

# Função para CloudFlare Origin
setup_cloudflare() {
    echo -e "${BLUE}🔐 Configurando CloudFlare Origin Certificate...${NC}"
    
    mkdir -p /etc/ssl/cloudflare
    
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}📋 Instruções CloudFlare:${NC}"
    echo -e "${YELLOW}1. Acesse: https://dash.cloudflare.com${NC}"
    echo -e "${YELLOW}2. Selecione seu domínio: $DOMAIN${NC}"
    echo -e "${YELLOW}3. Vá em: SSL/TLS → Origin Server${NC}"
    echo -e "${YELLOW}4. Clique: Create Certificate${NC}"
    echo -e "${YELLOW}5. Adicione: $DOMAIN e *.$DOMAIN${NC}"
    echo -e "${YELLOW}6. Validade: 15 anos${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    echo -e "${YELLOW}📝 Cole o CERTIFICADO (termine com linha vazia + CTRL+D):${NC}"
    cat > "/etc/ssl/cloudflare/$DOMAIN.pem"
    
    echo ""
    echo -e "${YELLOW}🔑 Cole a CHAVE PRIVADA (termine com linha vazia + CTRL+D):${NC}"
    cat > "/etc/ssl/cloudflare/$DOMAIN.key"
    chmod 600 "/etc/ssl/cloudflare/$DOMAIN.key"
    
    # Configurar Nginx
    cat > "$NGINX_CONF/$DOMAIN" << NGINX_CF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN $WWW_DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN $WWW_DOMAIN;
    
    root /var/www/html;
    index index.php index.html index.htm;
    
    # SSL CloudFlare Origin
    ssl_certificate /etc/ssl/cloudflare/$DOMAIN.pem;
    ssl_certificate_key /etc/ssl/cloudflare/$DOMAIN.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    
    # Headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    
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
    
    # PHP
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
    
    # Cache
    location ~* \.(jpg|jpeg|gif|png|css|js|ico|xml|woff|woff2)$ {
        expires 365d;
    }
    
    location ~ /\. {
        deny all;
    }
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
}
NGINX_CF
    
    nginx -t && systemctl reload nginx
    
    echo -e "${GREEN}✅ CloudFlare Origin Certificate configurado${NC}"
    echo -e "${YELLOW}⚠️  Configure no CloudFlare: SSL/TLS → Full (Strict)${NC}"
    
    return 0
}

# Função para auto-assinado
setup_selfsigned() {
    echo -e "${BLUE}🔐 Gerando certificado auto-assinado...${NC}"
    
    mkdir -p /etc/ssl/private
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "/etc/ssl/private/$DOMAIN.key" \
        -out "/etc/ssl/certs/$DOMAIN.crt" \
        -subj "/C=BR/ST=SP/L=SaoPaulo/O=Company/CN=$DOMAIN" > /dev/null 2>&1
    
    chmod 600 "/etc/ssl/private/$DOMAIN.key"
    
    # Configurar Nginx
    cat > "$NGINX_CONF/$DOMAIN" << NGINX_SELF
server {
    listen 80;
    server_name $DOMAIN $WWW_DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl;
    server_name $DOMAIN $WWW_DOMAIN;
    
    root /var/www/html;
    index index.php index.html index.htm;
    
    ssl_certificate /etc/ssl/certs/$DOMAIN.crt;
    ssl_certificate_key /etc/ssl/private/$DOMAIN.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
}
NGINX_SELF
    
    nginx -t && systemctl reload nginx
    
    echo -e "${GREEN}✅ Certificado auto-assinado configurado${NC}"
    return 0
}

# Função para escolher método SSL
choose_ssl_method() {
    if [[ -n "$SSL_METHOD" ]]; then
        case $SSL_METHOD in
            letsencrypt) setup_letsencrypt ;;
            cloudflare) setup_cloudflare ;;
            selfsigned) setup_selfsigned ;;
            *) echo -e "${RED}❌ Método inválido: $SSL_METHOD${NC}"; exit 1 ;;
        esac
    else
        # Auto-detectar melhor método
        if detect_cloudflare; then
            echo -e "${BLUE}CloudFlare detectado! Escolha:${NC}"
            echo "1) CloudFlare Origin Certificate (Recomendado)"
            echo "2) Let's Encrypt"
            echo "3) Certificado Auto-assinado"
        else
            echo -e "${BLUE}Escolha o método SSL:${NC}"
            echo "1) Let's Encrypt (Recomendado)"
            echo "2) CloudFlare Origin Certificate"
            echo "3) Certificado Auto-assinado"
        fi
        
        read -p "Opção [1]: " choice
        choice=${choice:-1}
        
        case $choice in
            1)
                if detect_cloudflare; then
                    setup_cloudflare
                else
                    setup_letsencrypt
                fi
                ;;
            2)
                if detect_cloudflare; then
                    setup_letsencrypt
                else
                    setup_cloudflare
                fi
                ;;
            3) setup_selfsigned ;;
            *) echo -e "${RED}❌ Opção inválida${NC}"; exit 1 ;;
        esac
    fi
}

# Função de teste
test_installation() {
    echo ""
    echo -e "${YELLOW}🧪 Testando instalação...${NC}"
    
    # Teste HTTP redirect
    if curl -sI "http://$DOMAIN" | grep -q "301\|302"; then
        echo -e "${GREEN}✅ Redirecionamento HTTP → HTTPS funcionando${NC}"
    else
        echo -e "${YELLOW}⚠️  Redirecionamento HTTP pode não estar funcionando${NC}"
    fi
    
    # Teste HTTPS
    if curl -ksI "https://$DOMAIN" | grep -q "200\|301\|302"; then
        echo -e "${GREEN}✅ HTTPS respondendo${NC}"
    else
        echo -e "${YELLOW}⚠️  HTTPS pode não estar acessível ainda${NC}"
    fi
    
    # Teste Nginx
    if systemctl is-active --quiet nginx; then
        echo -e "${GREEN}✅ Nginx está rodando${NC}"
    else
        echo -e "${RED}❌ Nginx não está rodando${NC}"
    fi
}

# Função principal
main() {
    echo -e "${YELLOW}🚀 Iniciando configuração...${NC}"
    echo ""
    
    # Instalar dependências
    install_dependencies
    
    # Criar configuração base
    create_nginx_base
    
    # Configurar SSL
    choose_ssl_method
    
    # Testar
    test_installation
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    ✅ CONFIGURAÇÃO CONCLUÍDA!         ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}🌐 Site disponível em:${NC}"
    echo -e "${GREEN}   https://$DOMAIN${NC}"
    echo -e "${GREEN}   https://$WWW_DOMAIN${NC}"
    echo ""
    
    if detect_cloudflare; then
        echo -e "${YELLOW}📝 Lembrete CloudFlare:${NC}"
        echo -e "${YELLOW}   - Configure SSL/TLS → Full (Strict)${NC}"
        echo -e "${YELLOW}   - Ative Always Use HTTPS${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}📁 Arquivos importantes:${NC}"
    echo -e "   Config Nginx: $NGINX_CONF/$DOMAIN"
    echo -e "   Logs: /var/log/nginx/$DOMAIN.*.log"
    echo ""
}

# Executar
main "$@"
