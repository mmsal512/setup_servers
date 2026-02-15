#!/bin/bash
###############################################################################
#  سكربت فحص شامل لجميع الخدمات والأدوات المثبتة
#  بناءً على ملف ultimate-secure-setup.yml
#  Compatible with: Ubuntu/Debian servers
###############################################################################

# ألوان للعرض
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# عدادات
TOTAL_CHECKS=0
PASSED=0
FAILED=0
WARNINGS=0

# ملف التقرير
REPORT_FILE="/tmp/server_health_report_$(date +%Y%m%d_%H%M%S).txt"

###############################################################################
# دوال المساعدة
###############################################################################

print_header() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${BOLD}$1${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo "" >> "$REPORT_FILE"
    echo "=== $1 ===" >> "$REPORT_FILE"
}

print_section() {
    echo ""
    echo -e "${MAGENTA}┌──────────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}│${NC} ${BOLD}$1${NC}"
    echo -e "${MAGENTA}└──────────────────────────────────────────────────┘${NC}"
    echo "" >> "$REPORT_FILE"
    echo "--- $1 ---" >> "$REPORT_FILE"
}

check_pass() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    PASSED=$((PASSED + 1))
    echo -e "  ${GREEN}✅ PASS${NC} - $1"
    echo "  [PASS] $1" >> "$REPORT_FILE"
}

check_fail() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    FAILED=$((FAILED + 1))
    echo -e "  ${RED}❌ FAIL${NC} - $1"
    echo "  [FAIL] $1" >> "$REPORT_FILE"
}

check_warn() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    WARNINGS=$((WARNINGS + 1))
    echo -e "  ${YELLOW}⚠️  WARN${NC} - $1"
    echo "  [WARN] $1" >> "$REPORT_FILE"
}

check_info() {
    echo -e "  ${BLUE}ℹ️  INFO${NC} - $1"
    echo "  [INFO] $1" >> "$REPORT_FILE"
}

# فحص وجود حزمة
check_package() {
    local pkg=$1
    local desc=${2:-$1}
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        check_pass "$desc مثبت"
        return 0
    else
        check_fail "$desc غير مثبت"
        return 1
    fi
}

# فحص خدمة systemd
check_service() {
    local svc=$1
    local desc=${2:-$1}
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        check_pass "خدمة $desc تعمل (active)"
        return 0
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        check_warn "خدمة $desc مفعلة لكن لا تعمل حالياً"
        return 1
    else
        check_fail "خدمة $desc لا تعمل وغير مفعلة"
        return 1
    fi
}

# فحص وجود ملف
check_file() {
    local file=$1
    local desc=${2:-$1}
    if [ -f "$file" ]; then
        check_pass "ملف $desc موجود"
        return 0
    else
        check_fail "ملف $desc غير موجود"
        return 1
    fi
}

# فحص وجود مجلد
check_dir() {
    local dir=$1
    local desc=${2:-$1}
    if [ -d "$dir" ]; then
        check_pass "مجلد $desc موجود"
        return 0
    else
        check_fail "مجلد $desc غير موجود"
        return 1
    fi
}

# فحص وجود أمر
check_command() {
    local cmd=$1
    local desc=${2:-$1}
    if command -v "$cmd" &>/dev/null; then
        local version
        version=$($cmd --version 2>/dev/null | head -1 || echo "متاح")
        check_pass "$desc متاح ($version)"
        return 0
    else
        check_fail "$desc غير متاح"
        return 1
    fi
}

# فحص منفذ
check_port() {
    local port=$1
    local desc=${2:-"Port $1"}
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        check_pass "$desc يستمع على المنفذ $port"
        return 0
    else
        check_fail "$desc لا يستمع على المنفذ $port"
        return 1
    fi
}

# فحص cron job
check_cron() {
    local pattern=$1
    local desc=${2:-$1}
    if crontab -l 2>/dev/null | grep -q "$pattern"; then
        check_pass "Cron job: $desc موجود"
        return 0
    elif grep -r "$pattern" /etc/cron* 2>/dev/null | grep -q .; then
        check_pass "Cron job: $desc موجود (system cron)"
        return 0
    else
        check_fail "Cron job: $desc غير موجود"
        return 1
    fi
}

###############################################################################
# بداية الفحص
###############################################################################

clear
echo "" > "$REPORT_FILE"
echo "تقرير فحص السيرفر - $(date)" >> "$REPORT_FILE"
echo "السيرفر: $(hostname)" >> "$REPORT_FILE"
echo "==========================================" >> "$REPORT_FILE"

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║       🔍 فحص شامل لجميع خدمات السيرفر الآمن                   ║"
echo "║       Based on: ultimate-secure-setup.yml                      ║"
echo "║                                                                ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${BLUE}📅 التاريخ: $(date)${NC}"
echo -e "${BLUE}🖥️  السيرفر: $(hostname)${NC}"
echo -e "${BLUE}🐧 النظام: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)${NC}"
echo -e "${BLUE}📊 Uptime: $(uptime -p 2>/dev/null || uptime)${NC}"

###############################################################################
# 1. فحص تحديثات النظام والحزم الأساسية
###############################################################################

print_header "1️⃣  تحديثات النظام والحزم الأساسية (System Updates & Base Packages)"

print_section "الحزم الأساسية المطلوبة"

BASE_PACKAGES=(
    "curl"
    "wget"
    "git"
    "vim"
    "nano"
    "htop"
    "iotop"
    "iftop"
    "tmux"
    "screen"
    "unzip"
    "zip"
    "tar"
    "gzip"
    "bzip2"
    "net-tools"
    "dnsutils"
    "mtr-tiny"
    "traceroute"
    "tcpdump"
    "nmap"
    "strace"
    "lsof"
    "sysstat"
    "ntp"
    "tree"
    "jq"
    "ncdu"
    "duf"
    "bat"
    "glances"
    "python3"
    "python3-pip"
    "software-properties-common"
    "apt-transport-https"
    "ca-certificates"
    "gnupg"
    "lsb-release"
    "build-essential"
    "gcc"
    "make"
    "autoconf"
    "automake"
    "pkg-config"
)

for pkg in "${BASE_PACKAGES[@]}"; do
    check_package "$pkg"
done

###############################################################################
# 2. فحص إعدادات SSH الآمنة
###############################################################################

print_header "2️⃣  إعدادات SSH الأمنية (SSH Security)"

print_section "فحص إعدادات SSH"

check_service "sshd" "SSH Daemon"
check_file "/etc/ssh/sshd_config" "SSH Config"

# فحص إعدادات أمنية محددة
if [ -f /etc/ssh/sshd_config ]; then
    # فحص تعطيل Root Login
    if grep -qE "^PermitRootLogin\s+(no|prohibit-password)" /etc/ssh/sshd_config 2>/dev/null; then
        check_pass "SSH: PermitRootLogin معطل أو مقيد"
    else
        check_warn "SSH: PermitRootLogin قد يكون مفعل"
    fi

    # فحص تعطيل Password Authentication
    if grep -qE "^PasswordAuthentication\s+no" /etc/ssh/sshd_config 2>/dev/null; then
        check_pass "SSH: Password Authentication معطل (مفاتيح فقط)"
    else
        check_warn "SSH: Password Authentication قد يكون مفعل"
    fi

    # فحص المنفذ
    SSH_PORT=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -n "$SSH_PORT" ] && [ "$SSH_PORT" != "22" ]; then
        check_pass "SSH: يعمل على منفذ مخصص ($SSH_PORT)"
    else
        check_warn "SSH: يعمل على المنفذ الافتراضي 22"
    fi

    # فحص MaxAuthTries
    if grep -qE "^MaxAuthTries\s+[1-3]" /etc/ssh/sshd_config 2>/dev/null; then
        check_pass "SSH: MaxAuthTries محدد بشكل آمن"
    else
        check_warn "SSH: MaxAuthTries غير محدد أو عالي"
    fi

    # فحص Protocol
    if grep -qE "^Protocol\s+2" /etc/ssh/sshd_config 2>/dev/null; then
        check_pass "SSH: Protocol 2 فقط"
    else
        check_info "SSH: Protocol setting (قد يكون افتراضياً 2 في الإصدارات الحديثة)"
    fi

    # فحص X11Forwarding
    if grep -qE "^X11Forwarding\s+no" /etc/ssh/sshd_config 2>/dev/null; then
        check_pass "SSH: X11Forwarding معطل"
    else
        check_warn "SSH: X11Forwarding قد يكون مفعل"
    fi

    # فحص ClientAliveInterval
    if grep -qE "^ClientAliveInterval" /etc/ssh/sshd_config 2>/dev/null; then
        check_pass "SSH: ClientAliveInterval مُعَد"
    else
        check_warn "SSH: ClientAliveInterval غير مُعَد"
    fi
fi

# فحص مفاتيح SSH
if [ -d ~/.ssh ] && ls ~/.ssh/*.pub &>/dev/null; then
    check_pass "SSH Keys: مفاتيح SSH موجودة"
else
    check_warn "SSH Keys: لا توجد مفاتيح SSH عامة"
fi

###############################################################################
# 3. فحص جدار الحماية (UFW/iptables)
###############################################################################

print_header "3️⃣  جدار الحماية (Firewall)"

print_section "UFW Firewall"

check_package "ufw" "UFW"

if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    if echo "$UFW_STATUS" | grep -q "active"; then
        check_pass "UFW: مفعل ونشط"
        
        # عرض القواعد
        check_info "قواعد UFW النشطة:"
        ufw status numbered 2>/dev/null | while read -r line; do
            if [ -n "$line" ]; then
                echo -e "    ${BLUE}$line${NC}"
            fi
        done
    else
        check_fail "UFW: غير مفعل"
    fi
else
    check_fail "UFW: غير مثبت"
fi

# فحص iptables
print_section "iptables"

if command -v iptables &>/dev/null; then
    IPTABLES_RULES=$(iptables -L -n 2>/dev/null | wc -l)
    if [ "$IPTABLES_RULES" -gt 8 ]; then
        check_pass "iptables: يحتوي على $IPTABLES_RULES سطر من القواعد"
    else
        check_info "iptables: قواعد أساسية فقط ($IPTABLES_RULES أسطر)"
    fi
fi

###############################################################################
# 4. فحص Fail2Ban
###############################################################################

print_header "4️⃣  Fail2Ban (حماية من الهجمات)"

check_package "fail2ban" "Fail2Ban"
check_service "fail2ban" "Fail2Ban"

if command -v fail2ban-client &>/dev/null; then
    # عدد الجيلز النشطة
    JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/\n/g' | wc -w)
    if [ "$JAILS" -gt 0 ]; then
        check_pass "Fail2Ban: $JAILS jail(s) نشطة"
        
        # تفاصيل كل jail
        fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g' | tr -s ' ' | while read -r jail; do
            jail=$(echo "$jail" | xargs)
            if [ -n "$jail" ]; then
                BANNED=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
                TOTAL_BANNED=$(fail2ban-client status "$jail" 2>/dev/null | grep "Total banned" | awk '{print $NF}')
                check_info "Jail '$jail': محظور حالياً=$BANNED, إجمالي=$TOTAL_BANNED"
            fi
        done
    else
        check_warn "Fail2Ban: لا توجد jails نشطة"
    fi
    
    check_file "/etc/fail2ban/jail.local" "Fail2Ban Custom Config"
fi

###############################################################################
# 5. فحص ClamAV (مضاد الفيروسات)
###############################################################################

print_header "5️⃣  ClamAV (مضاد الفيروسات)"

check_package "clamav" "ClamAV"
check_package "clamav-daemon" "ClamAV Daemon"
check_command "clamscan" "ClamAV Scanner"

check_service "clamav-daemon" "ClamAV Daemon"
check_service "clamav-freshclam" "ClamAV Freshclam (تحديث التعريفات)"

# فحص تحديث قاعدة البيانات
if [ -d /var/lib/clamav ]; then
    DB_FILES=$(ls /var/lib/clamav/*.c?d 2>/dev/null | wc -l)
    if [ "$DB_FILES" -gt 0 ]; then
        check_pass "ClamAV: قاعدة بيانات الفيروسات موجودة ($DB_FILES ملفات)"
        LAST_UPDATE=$(stat -c %y /var/lib/clamav/daily.c?d 2>/dev/null | cut -d' ' -f1)
        check_info "ClamAV: آخر تحديث لقاعدة البيانات: $LAST_UPDATE"
    else
        check_fail "ClamAV: قاعدة بيانات الفيروسات غير موجودة"
    fi
fi

###############################################################################
# 6. فحص Rootkit Hunter و chkrootkit
###############################################################################

print_header "6️⃣  كشف الـ Rootkits"

print_section "rkhunter"
check_package "rkhunter" "rkhunter"
check_command "rkhunter" "rkhunter"
check_file "/etc/rkhunter.conf" "rkhunter Config"

if command -v rkhunter &>/dev/null; then
    RKHUNTER_LOG="/var/log/rkhunter.log"
    if [ -f "$RKHUNTER_LOG" ]; then
        LAST_RUN=$(stat -c %y "$RKHUNTER_LOG" 2>/dev/null | cut -d' ' -f1)
        check_info "rkhunter: آخر فحص بتاريخ $LAST_RUN"
        WARNINGS_COUNT=$(grep -c "Warning" "$RKHUNTER_LOG" 2>/dev/null || echo 0)
        if [ "$WARNINGS_COUNT" -gt 0 ]; then
            check_warn "rkhunter: يوجد $WARNINGS_COUNT تحذير في آخر فحص"
        else
            check_pass "rkhunter: لا توجد تحذيرات في آخر فحص"
        fi
    fi
fi

print_section "chkrootkit"
check_package "chkrootkit" "chkrootkit"
check_command "chkrootkit" "chkrootkit"

###############################################################################
# 7. فحص Lynis (تدقيق أمني)
###############################################################################

print_header "7️⃣  Lynis (تدقيق أمني)"

check_package "lynis" "Lynis"
check_command "lynis" "Lynis"

if command -v lynis &>/dev/null; then
    LYNIS_VERSION=$(lynis --version 2>/dev/null || echo "غير معروف")
    check_info "Lynis Version: $LYNIS_VERSION"
    
    LYNIS_LOG="/var/log/lynis.log"
    if [ -f "$LYNIS_LOG" ]; then
        LAST_RUN=$(stat -c %y "$LYNIS_LOG" 2>/dev/null | cut -d' ' -f1)
        check_info "Lynis: آخر فحص بتاريخ $LAST_RUN"
        
        HARDENING_INDEX=$(grep "Hardening index" "$LYNIS_LOG" 2>/dev/null | tail -1 | grep -oP '\d+')
        if [ -n "$HARDENING_INDEX" ]; then
            if [ "$HARDENING_INDEX" -ge 70 ]; then
                check_pass "Lynis Hardening Index: $HARDENING_INDEX/100"
            elif [ "$HARDENING_INDEX" -ge 50 ]; then
                check_warn "Lynis Hardening Index: $HARDENING_INDEX/100 (يحتاج تحسين)"
            else
                check_fail "Lynis Hardening Index: $HARDENING_INDEX/100 (ضعيف)"
            fi
        fi
    fi
fi

###############################################################################
# 8. فحص AIDE (كشف تغيير الملفات)
###############################################################################

print_header "8️⃣  AIDE (كشف تغيير الملفات)"

check_package "aide" "AIDE"
check_command "aide" "AIDE"
check_file "/etc/aide/aide.conf" "AIDE Config"

if [ -f /var/lib/aide/aide.db ] || [ -f /var/lib/aide/aide.db.gz ]; then
    check_pass "AIDE: قاعدة البيانات موجودة"
else
    check_warn "AIDE: قاعدة البيانات غير مُنشأة (شغّل: aideinit)"
fi

###############################################################################
# 9. فحص أدوات المراقبة (Monitoring)
###############################################################################

print_header "9️⃣  أدوات المراقبة (Monitoring Tools)"

print_section "Prometheus & Node Exporter"

# Node Exporter
check_service "node_exporter" "Node Exporter"
check_port 9100 "Node Exporter"

if command -v node_exporter &>/dev/null || [ -f /usr/local/bin/node_exporter ]; then
    check_pass "Node Exporter: البرنامج موجود"
else
    # فحص إذا يعمل كـ Docker
    if docker ps 2>/dev/null | grep -q "node-exporter\|node_exporter"; then
        check_pass "Node Exporter: يعمل كـ Docker container"
    else
        check_fail "Node Exporter: غير مثبت"
    fi
fi

# Prometheus
check_service "prometheus" "Prometheus"
check_port 9090 "Prometheus"

if command -v prometheus &>/dev/null || [ -f /usr/local/bin/prometheus ]; then
    check_pass "Prometheus: البرنامج موجود"
elif docker ps 2>/dev/null | grep -q "prometheus"; then
    check_pass "Prometheus: يعمل كـ Docker container"
fi

check_file "/etc/prometheus/prometheus.yml" "Prometheus Config"

# فحص اتصال Prometheus
if curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/-/healthy 2>/dev/null | grep -q "200"; then
    check_pass "Prometheus: API يستجيب بنجاح"
else
    check_warn "Prometheus: API لا يستجيب"
fi

print_section "Grafana"

check_service "grafana-server" "Grafana"
check_port 3000 "Grafana"

if command -v grafana-server &>/dev/null || [ -f /usr/sbin/grafana-server ]; then
    check_pass "Grafana: البرنامج موجود"
elif docker ps 2>/dev/null | grep -q "grafana"; then
    check_pass "Grafana: يعمل كـ Docker container"
fi

# فحص اتصال Grafana
if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health 2>/dev/null | grep -q "200"; then
    check_pass "Grafana: API يستجيب بنجاح"
else
    check_warn "Grafana: API لا يستجيب"
fi

print_section "Alertmanager"

check_service "alertmanager" "Alertmanager"
check_port 9093 "Alertmanager"

if command -v alertmanager &>/dev/null || [ -f /usr/local/bin/alertmanager ]; then
    check_pass "Alertmanager: البرنامج موجود"
elif docker ps 2>/dev/null | grep -q "alertmanager"; then
    check_pass "Alertmanager: يعمل كـ Docker container"
fi

print_section "Netdata"

check_service "netdata" "Netdata"
check_port 19999 "Netdata"

if command -v netdata &>/dev/null; then
    check_pass "Netdata: البرنامج موجود"
elif docker ps 2>/dev/null | grep -q "netdata"; then
    check_pass "Netdata: يعمل كـ Docker container"
fi

print_section "Monit"

check_package "monit" "Monit"
check_service "monit" "Monit"
check_file "/etc/monit/monitrc" "Monit Config"

print_section "Glances"

check_command "glances" "Glances"

###############################################################################
# 10. فحص سكربت المراقبة المخصص
###############################################################################

print_header "🔟  سكربت المراقبة المخصص (Custom Monitoring Script)"

print_section "فحص سكربتات المراقبة"

# مسارات محتملة لسكربت المراقبة
MONITOR_PATHS=(
    "/usr/local/bin/server-monitor.sh"
    "/usr/local/bin/monitor.sh"
    "/usr/local/bin/monitoring.sh"
    "/usr/local/bin/health-check.sh"
    "/usr/local/bin/server_monitor.sh"
    "/opt/monitoring/monitor.sh"
    "/opt/scripts/monitor.sh"
    "/root/scripts/monitor.sh"
    "/root/monitor.sh"
    "/etc/monitoring/monitor.sh"
)

MONITOR_FOUND=false
for path in "${MONITOR_PATHS[@]}"; do
    if [ -f "$path" ]; then
        check_pass "سكربت المراقبة موجود: $path"
        MONITOR_FOUND=true
        
        # فحص صلاحيات التنفيذ
        if [ -x "$path" ]; then
            check_pass "سكربت المراقبة قابل للتنفيذ"
        else
            check_fail "سكربت المراقبة غير قابل للتنفيذ (chmod +x $path)"
        fi
        
        # فحص إذا كان مجدول في cron
        if crontab -l 2>/dev/null | grep -q "$path"; then
            check_pass "سكربت المراقبة مجدول في crontab"
            CRON_SCHEDULE=$(crontab -l 2>/dev/null | grep "$path")
            check_info "جدول التشغيل: $CRON_SCHEDULE"
        elif grep -r "$(basename $path)" /etc/cron* 2>/dev/null | grep -q .; then
            check_pass "سكربت المراقبة مجدول في system cron"
        else
            check_warn "سكربت المراقبة غير مجدول في cron"
        fi
        
        # فحص آخر تنفيذ
        MONITOR_LOG="/var/log/server-monitor.log"
        ALT_LOGS=(
            "/var/log/monitor.log"
            "/var/log/monitoring.log"
            "/var/log/health-check.log"
            "/tmp/monitor.log"
        )
        
        LOG_FOUND=false
        for log in "$MONITOR_LOG" "${ALT_LOGS[@]}"; do
            if [ -f "$log" ]; then
                LAST_RUN=$(stat -c %y "$log" 2>/dev/null | cut -d'.' -f1)
                check_pass "سجل المراقبة موجود: $log"
                check_info "آخر تحديث: $LAST_RUN"
                LOG_FOUND=true
                break
            fi
        done
        
        if [ "$LOG_FOUND" = false ]; then
            check_warn "سجل المراقبة غير موجود"
        fi
    fi
done

if [ "$MONITOR_FOUND" = false ]; then
    check_fail "لم يتم العثور على سكربت المراقبة في المسارات المعروفة"
    check_info "ابحث يدوياً: find / -name '*monitor*' -o -name '*health*' 2>/dev/null"
fi

# فحص سكربتات systemd للمراقبة
print_section "خدمات المراقبة في Systemd"

MONITOR_SERVICES=(
    "server-monitor"
    "monitoring"
    "health-check"
    "watchdog"
)

for svc in "${MONITOR_SERVICES[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "$svc"; then
        check_service "$svc" "خدمة $svc"
    fi
done

# فحص سكربتات المراقبة المخصصة عبر systemd timer
if systemctl list-timers 2>/dev/null | grep -qi "monitor\|health\|check"; then
    check_pass "يوجد Systemd Timer للمراقبة"
    systemctl list-timers 2>/dev/null | grep -i "monitor\|health\|check" | while read -r line; do
        check_info "Timer: $line"
    done
fi

###############################################################################
# 11. فحص Docker
###############################################################################

print_header "1️⃣1️⃣  Docker"

check_command "docker" "Docker"
check_service "docker" "Docker Service"

if command -v docker &>/dev/null; then
    DOCKER_VERSION=$(docker --version 2>/dev/null)
    check_info "Docker Version: $DOCKER_VERSION"
    
    # عدد الحاويات
    RUNNING=$(docker ps -q 2>/dev/null | wc -l)
    TOTAL=$(docker ps -a -q 2>/dev/null | wc -l)
    check_info "Docker Containers: $RUNNING تعمل من أصل $TOTAL"
    
    # عرض الحاويات العاملة
    if [ "$RUNNING" -gt 0 ]; then
        echo -e "  ${BLUE}الحاويات العاملة:${NC}"
        docker ps --format "    📦 {{.Names}} - {{.Image}} ({{.Status}})" 2>/dev/null
    fi
fi

# Docker Compose
check_command "docker-compose" "Docker Compose (v1)"
if command -v docker &>/dev/null && docker compose version &>/dev/null; then
    check_pass "Docker Compose v2 متاح"
fi

###############################################################################
# 12. فحص Nginx/Apache
###############################################################################

print_header "1️⃣2️⃣  خوادم الويب (Web Servers)"

print_section "Nginx"
check_package "nginx" "Nginx"
check_service "nginx" "Nginx"
check_port 80 "HTTP"
check_port 443 "HTTPS"

if command -v nginx &>/dev/null; then
    NGINX_VERSION=$(nginx -v 2>&1)
    check_info "Nginx: $NGINX_VERSION"
    
    # فحص صحة الإعدادات
    if nginx -t 2>/dev/null; then
        check_pass "Nginx: الإعدادات صحيحة"
    else
        check_fail "Nginx: خطأ في الإعدادات"
    fi
fi

print_section "Apache"
if dpkg -l apache2 2>/dev/null | grep -q "^ii"; then
    check_package "apache2" "Apache2"
    check_service "apache2" "Apache2"
fi

###############################################################################
# 13. فحص شهادات SSL/TLS
###############################################################################

print_header "1️⃣3️⃣  SSL/TLS و Let's Encrypt"

check_command "certbot" "Certbot"
check_package "certbot" "Certbot Package"

if command -v certbot &>/dev/null; then
    # عرض الشهادات
    CERTS=$(certbot certificates 2>/dev/null | grep "Certificate Name" | wc -l)
    if [ "$CERTS" -gt 0 ]; then
        check_pass "Let's Encrypt: $CERTS شهادة مثبتة"
        
        certbot certificates 2>/dev/null | grep -E "Certificate Name|Expiry Date" | while read -r line; do
            check_info "$line"
        done
    else
        check_warn "Let's Encrypt: لا توجد شهادات"
    fi
    
    # فحص التجديد التلقائي
    if systemctl list-timers 2>/dev/null | grep -q "certbot"; then
        check_pass "Certbot: التجديد التلقائي مفعل (systemd timer)"
    elif crontab -l 2>/dev/null | grep -q "certbot"; then
        check_pass "Certbot: التجديد التلقائي مفعل (cron)"
    else
        check_warn "Certbot: التجديد التلقائي غير مُعد"
    fi
fi

###############################################################################
# 14. فحص قواعد البيانات
###############################################################################

print_header "1️⃣4️⃣  قواعد البيانات (Databases)"

print_section "MySQL/MariaDB"
if dpkg -l mariadb-server 2>/dev/null | grep -q "^ii" || dpkg -l mysql-server 2>/dev/null | grep -q "^ii"; then
    check_package "mariadb-server" "MariaDB" 2>/dev/null || check_package "mysql-server" "MySQL"
    check_service "mariadb" "MariaDB" 2>/dev/null || check_service "mysql" "MySQL"
    check_port 3306 "MySQL/MariaDB"
fi

print_section "PostgreSQL"
if dpkg -l postgresql 2>/dev/null | grep -q "^ii"; then
    check_package "postgresql" "PostgreSQL"
    check_service "postgresql" "PostgreSQL"
    check_port 5432 "PostgreSQL"
fi

print_section "Redis"
if dpkg -l redis-server 2>/dev/null | grep -q "^ii"; then
    check_package "redis-server" "Redis"
    check_service "redis-server" "Redis"
    check_port 6379 "Redis"
fi

print_section "MongoDB"
if dpkg -l mongodb-org 2>/dev/null | grep -q "^ii" || dpkg -l mongod 2>/dev/null | grep -q "^ii"; then
    check_service "mongod" "MongoDB"
    check_port 27017 "MongoDB"
fi

###############################################################################
# 15. فحص النسخ الاحتياطي
###############################################################################

print_header "1️⃣5️⃣  النسخ الاحتياطي (Backup)"

print_section "أدوات النسخ الاحتياطي"

check_command "rsync" "rsync"
check_command "borgbackup" "BorgBackup"
check_command "restic" "Restic"
check_command "duplicity" "Duplicity"

# فحص سكربتات النسخ الاحتياطي
BACKUP_PATHS=(
    "/usr/local/bin/backup.sh"
    "/usr/local/bin/server-backup.sh"
    "/opt/backup/backup.sh"
    "/root/backup.sh"
    "/root/scripts/backup.sh"
)

for path in "${BACKUP_PATHS[@]}"; do
    if [ -f "$path" ]; then
        check_pass "سكربت النسخ الاحتياطي: $path"
        if [ -x "$path" ]; then
            check_pass "قابل للتنفيذ: $path"
        fi
    fi
done

# فحص cron للنسخ الاحتياطي
if crontab -l 2>/dev/null | grep -qi "backup"; then
    check_pass "النسخ الاحتياطي مجدول في cron"
elif grep -r "backup" /etc/cron* 2>/dev/null | grep -q .; then
    check_pass "النسخ الاحتياطي مجدول في system cron"
else
    check_warn "لم يتم العثور على جدولة للنسخ الاحتياطي"
fi

###############################################################################
# 16. فحص Logrotate والسجلات
###############################################################################

print_header "1️⃣6️⃣  إدارة السجلات (Log Management)"

check_package "logrotate" "Logrotate"
check_service "rsyslog" "Rsyslog"

check_file "/etc/logrotate.conf" "Logrotate Config"
check_dir "/etc/logrotate.d" "Logrotate.d"

# فحص مساحة السجلات
LOG_SIZE=$(du -sh /var/log 2>/dev/null | awk '{print $1}')
check_info "حجم /var/log: $LOG_SIZE"

# فحص journald
if command -v journalctl &>/dev/null; then
    JOURNAL_SIZE=$(journalctl --disk-usage 2>/dev/null | grep -oP '[\d.]+[GMKT]')
    check_info "حجم Journal: $JOURNAL_SIZE"
fi

###############################################################################
# 17. فحص Auditd
###############################################################################

print_header "1️⃣7️⃣  Auditd (تدقيق النظام)"

check_package "auditd" "Auditd"
check_service "auditd" "Auditd"
check_file "/etc/audit/auditd.conf" "Auditd Config"
check_file "/etc/audit/rules.d/audit.rules" "Audit Rules"

if command -v auditctl &>/dev/null; then
    AUDIT_RULES=$(auditctl -l 2>/dev/null | wc -l)
    if [ "$AUDIT_RULES" -gt 0 ]; then
        check_pass "Auditd: $AUDIT_RULES قاعدة تدقيق نشطة"
    else
        check_warn "Auditd: لا توجد قواعد تدقيق"
    fi
fi

###############################################################################
# 18. فحص إعدادات Sysctl (Kernel Hardening)
###############################################################################

print_header "1️⃣8️⃣  تقوية Kernel (Sysctl Hardening)"

print_section "إعدادات الشبكة الأمنية"

# فحص إعدادات sysctl المهمة
declare -A SYSCTL_CHECKS=(
    ["net.ipv4.ip_forward"]="0:IP Forwarding معطل"
    ["net.ipv4.conf.all.rp_filter"]="1:Reverse Path Filtering مفعل"
    ["net.ipv4.conf.all.accept_redirects"]="0:ICMP Redirects معطل"
    ["net.ipv4.conf.all.send_redirects"]="0:Send Redirects معطل"
    ["net.ipv4.conf.all.accept_source_route"]="0:Source Routing معطل"
    ["net.ipv4.conf.all.log_martians"]="1:Martian Logging مفعل"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1:Broadcast ICMP معطل"
    ["net.ipv4.tcp_syncookies"]="1:SYN Cookies مفعل"
    ["net.ipv6.conf.all.accept_redirects"]="0:IPv6 Redirects معطل"
    ["kernel.randomize_va_space"]="2:ASLR مفعل"
    ["fs.protected_hardlinks"]="1:Protected Hardlinks"
    ["fs.protected_symlinks"]="1:Protected Symlinks"
)

for key in "${!SYSCTL_CHECKS[@]}"; do
    IFS=':' read -r expected desc <<< "${SYSCTL_CHECKS[$key]}"
    actual=$(sysctl -n "$key" 2>/dev/null)
    if [ "$actual" = "$expected" ]; then
        check_pass "Sysctl: $desc ($key=$actual)"
    elif [ -n "$actual" ]; then
        check_warn "Sysctl: $desc ($key=$actual, المتوقع=$expected)"
    fi
done

###############################################################################
# 19. فحص AppArmor/SELinux
###############################################################################

print_header "1️⃣9️⃣  AppArmor / SELinux"

print_section "AppArmor"
if command -v apparmor_status &>/dev/null; then
    check_pass "AppArmor: مثبت"
    PROFILES=$(apparmor_status 2>/dev/null | grep "profiles are loaded" | grep -oP '\d+')
    ENFORCE=$(apparmor_status 2>/dev/null | grep "profiles are in enforce" | grep -oP '\d+')
    if [ -n "$PROFILES" ]; then
        check_info "AppArmor: $PROFILES profile محمل, $ENFORCE في وضع enforce"
    fi
else
    check_info "AppArmor: غير مثبت"
fi

print_section "SELinux"
if command -v sestatus &>/dev/null; then
    SESTATUS=$(sestatus 2>/dev/null | grep "SELinux status" | awk '{print $NF}')
    check_info "SELinux: $SESTATUS"
else
    check_info "SELinux: غير مثبت (عادي لـ Ubuntu/Debian)"
fi

###############################################################################
# 20. فحص إعدادات الشبكة
###############################################################################

print_header "2️⃣0️⃣  إعدادات الشبكة (Network)"

print_section "واجهات الشبكة"

# عرض واجهات الشبكة
ip -4 addr show 2>/dev/null | grep -E "inet " | while read -r line; do
    check_info "IPv4: $line"
done

# DNS
check_info "DNS Servers:"
if [ -f /etc/resolv.conf ]; then
    grep "nameserver" /etc/resolv.conf | while read -r line; do
        echo -e "    ${BLUE}$line${NC}"
    done
fi

# فحص الاتصال بالإنترنت
if ping -c 1 -W 3 8.8.8.8 &>/dev/null; then
    check_pass "الاتصال بالإنترنت يعمل"
else
    check_fail "لا يوجد اتصال بالإنترنت"
fi

if ping -c 1 -W 3 google.com &>/dev/null; then
    check_pass "DNS يعمل بشكل صحيح"
else
    check_warn "DNS قد لا يعمل بشكل صحيح"
fi

###############################################################################
# 21. فحص المستخدمين والصلاحيات
###############################################################################

print_header "2️⃣1️⃣  المستخدمون والصلاحيات (Users & Permissions)"

print_section "فحص المستخدمين"

# مستخدمون بدون كلمة مرور
EMPTY_PASS=$(awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1}' /etc/shadow 2>/dev/null | grep -v "^#" | wc -l)
check_info "مستخدمون بدون كلمة مرور أو مقفلين: $EMPTY_PASS"

# فحص UID 0
ROOT_USERS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null)
ROOT_COUNT=$(echo "$ROOT_USERS" | wc -w)
if [ "$ROOT_COUNT" -eq 1 ]; then
    check_pass "مستخدم واحد فقط بـ UID 0 (root)"
else
    check_fail "يوجد $ROOT_COUNT مستخدم بـ UID 0: $ROOT_USERS"
fi

# فحص sudo group
SUDO_USERS=$(getent group sudo 2>/dev/null | cut -d: -f4)
check_info "مستخدمو sudo: $SUDO_USERS"

# فحص صلاحيات ملفات حساسة
SENSITIVE_FILES=(
    "/etc/passwd:644"
    "/etc/shadow:640"
    "/etc/group:644"
    "/etc/gshadow:640"
    "/etc/ssh/sshd_config:644"
)

print_section "صلاحيات الملفات الحساسة"

for entry in "${SENSITIVE_FILES[@]}"; do
    IFS=':' read -r file expected_perm <<< "$entry"
    if [ -f "$file" ]; then
        actual_perm=$(stat -c "%a" "$file" 2>/dev/null)
        if [ "$actual_perm" = "$expected_perm" ] || [ "$actual_perm" -le "$expected_perm" ]; then
            check_pass "$file: الصلاحيات صحيحة ($actual_perm)"
        else
            check_warn "$file: الصلاحيات $actual_perm (المتوقع: $expected_perm)"
        fi
    fi
done

###############################################################################
# 22. فحص مساحة القرص والذاكرة
###############################################################################

print_header "2️⃣2️⃣  موارد النظام (System Resources)"

print_section "مساحة القرص"

df -h / /home /var /tmp 2>/dev/null | tail -n +2 | while read -r line; do
    USAGE=$(echo "$line" | awk '{print $5}' | tr -d '%')
    MOUNT=$(echo "$line" | awk '{print $6}')
    if [ "$USAGE" -lt 80 ]; then
        check_pass "القرص $MOUNT: ${USAGE}% مستخدم"
    elif [ "$USAGE" -lt 90 ]; then
        check_warn "القرص $MOUNT: ${USAGE}% مستخدم (قارب الامتلاء)"
    else
        check_fail "القرص $MOUNT: ${USAGE}% مستخدم (حرج!)"
    fi
done

print_section "الذاكرة"

MEM_TOTAL=$(free -m | awk '/^Mem:/ {print $2}')
MEM_USED=$(free -m | awk '/^Mem:/ {print $3}')
MEM_PERCENT=$((MEM_USED * 100 / MEM_TOTAL))

if [ "$MEM_PERCENT" -lt 80 ]; then
    check_pass "الذاكرة: ${MEM_PERCENT}% مستخدمة (${MEM_USED}MB / ${MEM_TOTAL}MB)"
elif [ "$MEM_PERCENT" -lt 90 ]; then
    check_warn "الذاكرة: ${MEM_PERCENT}% مستخدمة (${MEM_USED}MB / ${MEM_TOTAL}MB)"
else
    check_fail "الذاكرة: ${MEM_PERCENT}% مستخدمة (${MEM_USED}MB / ${MEM_TOTAL}MB)"
fi

SWAP_TOTAL=$(free -m | awk '/^Swap:/ {print $2}')
if [ "$SWAP_TOTAL" -gt 0 ]; then
    SWAP_USED=$(free -m | awk '/^Swap:/ {print $3}')
    check_info "Swap: ${SWAP_USED}MB / ${SWAP_TOTAL}MB"
else
    check_warn "Swap: غير مُعد"
fi

print_section "الحمل (Load Average)"

LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{print $1}')
CPUS=$(nproc 2>/dev/null)
LOAD_INT=${LOAD%.*}

if [ "${LOAD_INT:-0}" -lt "$CPUS" ]; then
    check_pass "Load Average: $LOAD (CPUs: $CPUS)"
else
    check_warn "Load Average: $LOAD عالي (CPUs: $CPUS)"
fi

###############################################################################
# 23. فحص NTP/وقت النظام
###############################################################################

print_header "2️⃣3️⃣  مزامنة الوقت (NTP)"

check_service "ntp" "NTP" 2>/dev/null || check_service "ntpd" "NTPd" 2>/dev/null || check_service "chronyd" "Chrony" 2>/dev/null || check_service "systemd-timesyncd" "systemd-timesyncd"

if timedatectl 2>/dev/null | grep -q "synchronized: yes"; then
    check_pass "الوقت متزامن"
else
    check_warn "الوقت قد لا يكون متزامن"
fi

check_info "الوقت الحالي: $(date)"
check_info "المنطقة الزمنية: $(timedatectl 2>/dev/null | grep "Time zone" | awk '{print $3}')"

###############################################################################
# 24. فحص Unattended Upgrades
###############################################################################

print_header "2️⃣4️⃣  التحديثات التلقائية (Unattended Upgrades)"

check_package "unattended-upgrades" "Unattended Upgrades"
check_file "/etc/apt/apt.conf.d/50unattended-upgrades" "Unattended Upgrades Config"
check_file "/etc/apt/apt.conf.d/20auto-upgrades" "Auto Upgrades Config"

if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    if grep -q 'APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
        check_pass "التحديثات التلقائية مفعلة"
    else
        check_warn "التحديثات التلقائية قد تكون غير مفعلة"
    fi
fi

###############################################################################
# 25. فحص ModSecurity / WAF
###############################################################################

print_header "2️⃣5️⃣  WAF (ModSecurity)"

if dpkg -l libapache2-mod-security2 2>/dev/null | grep -q "^ii" || dpkg -l libnginx-mod-security 2>/dev/null | grep -q "^ii"; then
    check_pass "ModSecurity مثبت"
else
    check_info "ModSecurity غير مثبت"
fi

###############################################################################
# 26. فحص Wireguard/OpenVPN
###############################################################################

print_header "2️⃣6️⃣  VPN"

print_section "WireGuard"
if command -v wg &>/dev/null; then
    check_pass "WireGuard مثبت"
    if wg show 2>/dev/null | grep -q "interface"; then
        check_pass "WireGuard: واجهة نشطة"
    else
        check_info "WireGuard: لا توجد واجهة نشطة"
    fi
fi

print_section "OpenVPN"
if command -v openvpn &>/dev/null; then
    check_pass "OpenVPN مثبت"
    check_service "openvpn" "OpenVPN"
fi

###############################################################################
# 27. فحص Cron Jobs المهمة
###############################################################################

print_header "2️⃣7️⃣  Cron Jobs المجدولة"

echo -e "${BLUE}  المهام المجدولة الحالية:${NC}"
if crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$"; then
    crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | while read -r line; do
        check_info "Cron: $line"
    done
else
    check_warn "لا توجد مهام مجدولة في crontab"
fi

# فحص system cron
for crondir in /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$crondir" ]; then
        COUNT=$(ls "$crondir" 2>/dev/null | wc -l)
        check_info "$crondir: $COUNT مهمة"
    fi
done

###############################################################################
# 28. فحص حاويات Docker الأمنية
###############################################################################

print_header "2️⃣8️⃣  أدوات أمنية إضافية"

# فحص أدوات إضافية
print_section "أدوات أمنية"

SECURITY_TOOLS=(
    "tripwire:Tripwire"
    "tiger:Tiger"
    "debsums:Debsums"
    "needrestart:Needrestart"
    "apt-listchanges:APT Listchanges"
    "debsecan:Debsecan"
)

for tool_entry in "${SECURITY_TOOLS[@]}"; do
    IFS=':' read -r tool desc <<< "$tool_entry"
    if command -v "$tool" &>/dev/null || dpkg -l "$tool" 2>/dev/null | grep -q "^ii"; then
        check_pass "$desc مثبت"
    fi
done

###############################################################################
# 29. فحص حالة الخدمات الفاشلة
###############################################################################

print_header "2️⃣9️⃣  الخدمات الفاشلة (Failed Services)"

FAILED_SERVICES=$(systemctl --failed --no-pager 2>/dev/null | grep "failed" | wc -l)
if [ "$FAILED_SERVICES" -eq 0 ]; then
    check_pass "لا توجد خدمات فاشلة"
else
    check_fail "يوجد $FAILED_SERVICES خدمة فاشلة:"
    systemctl --failed --no-pager 2>/dev/null | grep "failed" | while read -r line; do
        echo -e "    ${RED}$line${NC}"
    done
fi

###############################################################################
# 30. فحص الاستماع على المنافذ
###############################################################################

print_header "3️⃣0️⃣  المنافذ المفتوحة (Open Ports)"

echo -e "${BLUE}  المنافذ المستمعة:${NC}"
ss -tlnp 2>/dev/null | grep LISTEN | while read -r line; do
    PORT=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
    PROC=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+')
    echo -e "    ${BLUE}📡 Port $PORT${NC} - $PROC"
done

###############################################################################
# التقرير النهائي
###############################################################################

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                                ║${NC}"
echo -e "${CYAN}║                    📊 التقرير النهائي                            ║${NC}"
echo -e "${CYAN}║                                                                ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}                                                                ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  إجمالي الفحوصات : ${BOLD}$TOTAL_CHECKS${NC}                                    ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${GREEN}✅ ناجح          : $PASSED${NC}                                      ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${RED}❌ فاشل          : $FAILED${NC}                                      ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ${YELLOW}⚠️  تحذيرات       : $WARNINGS${NC}                                      ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}                                                                ${CYAN}║${NC}"

# حساب النسبة المئوية
if [ "$TOTAL_CHECKS" -gt 0 ]; then
    SCORE=$((PASSED * 100 / TOTAL_CHECKS))
    if [ "$SCORE" -ge 90 ]; then
        GRADE="A+ 🏆"
        GRADE_COLOR=$GREEN
    elif [ "$SCORE" -ge 80 ]; then
        GRADE="A  ⭐"
        GRADE_COLOR=$GREEN
    elif [ "$SCORE" -ge 70 ]; then
        GRADE="B  👍"
        GRADE_COLOR=$YELLOW
    elif [ "$SCORE" -ge 60 ]; then
        GRADE="C  ⚡"
        GRADE_COLOR=$YELLOW
    else
        GRADE="D  ⚠️"
        GRADE_COLOR=$RED
    fi

    echo -e "${CYAN}║${NC}  ${BOLD}النتيجة: ${GRADE_COLOR}${SCORE}% - التقييم: ${GRADE}${NC}                           ${CYAN}║${NC}"
fi

echo -e "${CYAN}║${NC}                                                                ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"

echo ""
echo -e "${BLUE}📄 التقرير المفصل محفوظ في: ${BOLD}$REPORT_FILE${NC}"
echo ""

# حفظ الملخص في ملف التقرير
echo "" >> "$REPORT_FILE"
echo "==========================================" >> "$REPORT_FILE"
echo "الملخص:" >> "$REPORT_FILE"
echo "  إجمالي الفحوصات: $TOTAL_CHECKS" >> "$REPORT_FILE"
echo "  ناجح: $PASSED" >> "$REPORT_FILE"
echo "  فاشل: $FAILED" >> "$REPORT_FILE"
echo "  تحذيرات: $WARNINGS" >> "$REPORT_FILE"
echo "  النتيجة: ${SCORE:-0}%" >> "$REPORT_FILE"
echo "==========================================" >> "$REPORT_FILE"

# كود الخروج
if [ "$FAILED" -eq 0 ]; then
    exit 0
elif [ "$FAILED" -le 5 ]; then
    exit 1
else
    exit 2
fi
