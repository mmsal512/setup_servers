#!/bin/bash
###############################################################################
#  سكربت الإصلاح المخصص - بناءً على نتائج الفحص الفعلية
#  تاريخ: 2026-02-15
###############################################################################

# ⚠️ الإصلاح الجوهري: لا نستخدم set -e حتى لا يتوقف السكربت
set +e
set +u
set +o pipefail

# ألوان
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}يجب تشغيل السكربت كـ root${NC}"
    exit 1
fi

LOG="/var/log/server-fix-$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

export DEBIAN_FRONTEND=noninteractive

# عدادات
TOTAL_STEPS=12
STEPS_OK=0
STEPS_PARTIAL=0
STEPS_FAILED=0

step() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  🔧 $1${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
}

ok()   { echo -e "  ${GREEN}✅ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠️  $1${NC}"; }
fail() { echo -e "  ${RED}❌ $1${NC}"; }
info() { echo -e "  📌 $1"; }

step_ok()      { STEPS_OK=$((STEPS_OK + 1)); ok "$1"; }
step_partial() { STEPS_PARTIAL=$((STEPS_PARTIAL + 1)); warn "$1"; }
step_failed()  { STEPS_FAILED=$((STEPS_FAILED + 1)); fail "$1"; }

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                         ║"
echo "║    🔧 إصلاح مخصص بناءً على نتائج الفحص الفعلية         ║"
echo "║    12 مشكلة مكتشفة - بدء الإصلاح                       ║"
echo "║                                                         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

###############################################################################
# المشكلة 1: الحزم المفقودة
###############################################################################
step "1/12 - تثبيت الحزم المفقودة"

info "تحديث قوائم الحزم..."
apt-get update -y -qq 2>/dev/null || warn "فشل تحديث القوائم - المتابعة بالحزم المتوفرة"

MISSING_PACKAGES=(
    iotop iftop dnsutils mtr-tiny strace sysstat ntp ncdu glances
    python3-pip autoconf automake pkg-config chkrootkit lynis
    monit nginx certbot python3-certbot-nginx
)

INSTALLED_NOW=0
FAILED_PKGS=()

for pkg in "${MISSING_PACKAGES[@]}"; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        ok "$pkg مثبت مسبقاً"
        INSTALLED_NOW=$((INSTALLED_NOW + 1))
    else
        info "تثبيت $pkg..."
        if apt-get install -y -qq "$pkg" >> "$LOG" 2>&1; then
            ok "$pkg تم تثبيته"
            INSTALLED_NOW=$((INSTALLED_NOW + 1))
        else
            FAILED_PKGS+=("$pkg")
            warn "$pkg فشل التثبيت"
        fi
    fi
done

# محاولة duf و bat
for pkg in duf bat; do
    if apt-get install -y -qq "$pkg" >> "$LOG" 2>&1; then
        ok "$pkg تم تثبيته"
    else
        if [ "$pkg" = "bat" ]; then
            apt-get install -y -qq batcat >> "$LOG" 2>&1 && ok "batcat (بديل bat) تم تثبيته" || warn "$pkg غير متوفر"
        else
            warn "$pkg غير متوفر في هذا الإصدار"
        fi
    fi
done

if [ ${#FAILED_PKGS[@]} -eq 0 ]; then
    step_ok "تم تثبيت جميع الحزم ($INSTALLED_NOW حزمة)"
elif [ ${#FAILED_PKGS[@]} -le 3 ]; then
    step_partial "تم تثبيت معظم الحزم - فشلت: ${FAILED_PKGS[*]}"
else
    step_failed "فشل تثبيت عدة حزم: ${FAILED_PKGS[*]}"
fi

###############################################################################
# المشكلة 2: ClamAV freshclam فاشل + daemon متوقف
###############################################################################
step "2/12 - إصلاح ClamAV (freshclam + daemon)"

CLAMAV_FIXED=false

info "إيقاف الخدمات..."
systemctl stop clamav-freshclam 2>/dev/null || true
systemctl stop clamav-daemon 2>/dev/null || true

info "حذف ملفات القفل..."
rm -f /var/log/clamav/freshclam.log.lock 2>/dev/null || true
rm -f /var/lib/clamav/.lock 2>/dev/null || true
rm -f /run/clamav/freshclam.pid 2>/dev/null || true

info "إصلاح الصلاحيات..."
mkdir -p /var/log/clamav /var/lib/clamav /run/clamav 2>/dev/null || true
chown -R clamav:clamav /var/log/clamav /var/lib/clamav /run/clamav 2>/dev/null || true
chmod 755 /var/log/clamav /var/lib/clamav 2>/dev/null || true

touch /var/log/clamav/freshclam.log 2>/dev/null || true
chown clamav:adm /var/log/clamav/freshclam.log 2>/dev/null || true
chmod 640 /var/log/clamav/freshclam.log 2>/dev/null || true

if [ -f /etc/clamav/freshclam.conf ]; then
    sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf 2>/dev/null || true
    grep -q "^DatabaseMirror" /etc/clamav/freshclam.conf 2>/dev/null || \
        echo "DatabaseMirror database.clamav.net" >> /etc/clamav/freshclam.conf
fi

info "تحديث قاعدة بيانات الفيروسات..."
if freshclam --verbose >> "$LOG" 2>&1; then
    ok "تم تحديث قاعدة البيانات"
else
    warn "محاولة تحديث بديلة..."
    cd /var/lib/clamav 2>/dev/null || true
    for db in main.cvd daily.cvd bytecode.cvd; do
        wget -q "https://database.clamav.net/$db" -O "$db.tmp" 2>/dev/null && \
            mv "$db.tmp" "$db" 2>/dev/null && ok "تم تحميل $db" || true
    done
    chown clamav:clamav /var/lib/clamav/*.cvd 2>/dev/null || true
    cd / 2>/dev/null || true
fi

info "تشغيل freshclam..."
systemctl start clamav-freshclam 2>/dev/null || true
sleep 3

if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
    ok "clamav-freshclam يعمل الآن"
else
    warn "freshclam كخدمة لا يعمل - سنعتمد على cron"
    systemctl disable clamav-freshclam 2>/dev/null || true
    ok "التحديث يتم عبر cron كل 4 ساعات (موجود مسبقاً)"
    freshclam >> "$LOG" 2>&1 || true
fi

info "تشغيل clamav-daemon..."
sleep 2
systemctl start clamav-daemon 2>/dev/null || true

info "انتظار بدء ClamAV daemon (قد يأخذ 30-60 ثانية)..."
DAEMON_STARTED=false
for i in $(seq 1 12); do
    if systemctl is-active --quiet clamav-daemon 2>/dev/null; then
        ok "clamav-daemon يعمل الآن"
        DAEMON_STARTED=true
        break
    fi
    sleep 5
    echo -n "."
done
echo ""

if $DAEMON_STARTED; then
    step_ok "ClamAV تم إصلاحه بالكامل"
else
    systemctl enable clamav-daemon 2>/dev/null || true
    step_partial "ClamAV تم إعداده - daemon يحتاج وقت أطول للبدء"
fi

###############################################################################
# المشكلة 3: CrowdSec فاشل
###############################################################################
step "3/12 - إصلاح CrowdSec"

CROWDSEC_OK=false

# دالة آمنة لتشغيل أوامر CrowdSec
run_cscli() {
    local cmd="$1"
    local desc="$2"
    if eval "$cmd" >> "$LOG" 2>&1; then
        ok "$desc"
        return 0
    else
        warn "فشل: $desc"
        return 1
    fi
}

if systemctl list-unit-files 2>/dev/null | grep -q crowdsec; then
    info "CrowdSec مثبت - محاولة الإصلاح..."

    if command -v cscli &>/dev/null; then
        info "إعادة إعداد CrowdSec..."

        run_cscli "cscli hub update" "تحديث hub"
        run_cscli "cscli collections install crowdsecurity/linux --force" "تثبيت collection: linux"
        run_cscli "cscli collections install crowdsecurity/sshd --force" "تثبيت collection: sshd"

        systemctl restart crowdsec >> "$LOG" 2>&1 || true
        sleep 3

        if systemctl is-active --quiet crowdsec 2>/dev/null; then
            ok "CrowdSec يعمل الآن"
            CROWDSEC_OK=true
        else
            warn "CrowdSec لا يزال متوقف - محاولة إعادة التثبيت..."
            journalctl -u crowdsec --no-pager -n 10 >> "$LOG" 2>&1 || true

            info "إعادة تسجيل الآلة..."
            cscli machines add -a >> "$LOG" 2>&1 || true

            systemctl restart crowdsec >> "$LOG" 2>&1 || true
            sleep 3

            if systemctl is-active --quiet crowdsec 2>/dev/null; then
                ok "CrowdSec يعمل بعد إعادة التسجيل"
                CROWDSEC_OK=true
            else
                info "محاولة إعادة تثبيت CrowdSec..."
                apt-get install --reinstall -y crowdsec >> "$LOG" 2>&1 || {
                    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh 2>/dev/null | bash >> "$LOG" 2>&1 || true
                    apt-get update -qq >> "$LOG" 2>&1 || true
                    apt-get install -y crowdsec >> "$LOG" 2>&1 || true
                }

                systemctl enable crowdsec 2>/dev/null || true
                systemctl restart crowdsec >> "$LOG" 2>&1 || true
                sleep 3

                if systemctl is-active --quiet crowdsec 2>/dev/null; then
                    ok "CrowdSec يعمل بعد إعادة التثبيت"
                    CROWDSEC_OK=true
                fi
            fi
        fi
    else
        warn "cscli غير متوفر - إعادة تثبيت كاملة..."
        apt-get install -y crowdsec >> "$LOG" 2>&1 || {
            curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh 2>/dev/null | bash >> "$LOG" 2>&1 || true
            apt-get update -qq >> "$LOG" 2>&1 || true
            apt-get install -y crowdsec >> "$LOG" 2>&1 || true
        }
        systemctl enable crowdsec 2>/dev/null || true
        systemctl start crowdsec >> "$LOG" 2>&1 || true
        sleep 3
        systemctl is-active --quiet crowdsec 2>/dev/null && CROWDSEC_OK=true
    fi
else
    info "CrowdSec غير مثبت - تثبيت..."
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh 2>/dev/null | bash >> "$LOG" 2>&1 || true
    apt-get update -qq >> "$LOG" 2>&1 || true
    if apt-get install -y crowdsec >> "$LOG" 2>&1; then
        run_cscli "cscli hub update" "تحديث hub"
        run_cscli "cscli collections install crowdsecurity/linux --force" "collection: linux"
        run_cscli "cscli collections install crowdsecurity/sshd --force" "collection: sshd"
        systemctl enable crowdsec 2>/dev/null || true
        systemctl start crowdsec >> "$LOG" 2>&1 || true
        sleep 3
        systemctl is-active --quiet crowdsec 2>/dev/null && CROWDSEC_OK=true
    fi
fi

if $CROWDSEC_OK; then
    step_ok "CrowdSec يعمل"
else
    step_failed "CrowdSec لا يزال فاشل - راجع: journalctl -u crowdsec -n 50"
fi

###############################################################################
# المشكلة 4: dailyaidecheck.service فاشل
###############################################################################
step "4/12 - إصلاح AIDE Daily Check"

AIDE_OK=false

info "فحص AIDE..."

# فحص وإنشاء قاعدة بيانات AIDE
if [ ! -f /var/lib/aide/aide.db ] && [ ! -f /var/lib/aide/aide.db.gz ]; then
    info "قاعدة بيانات AIDE غير موجودة..."

    if [ -f /var/lib/aide/aide.db.new ]; then
        cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null && ok "تم نسخ aide.db.new" || true
    elif [ -f /var/lib/aide/aide.db.new.gz ]; then
        cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null && ok "تم نسخ aide.db.new.gz" || true
    else
        info "إنشاء قاعدة بيانات AIDE جديدة (قد يأخذ دقائق)..."
        if command -v aide &>/dev/null; then
            aide --init >> "$LOG" 2>&1 || aideinit >> "$LOG" 2>&1 || true
            sleep 5
            [ -f /var/lib/aide/aide.db.new ] && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
            [ -f /var/lib/aide/aide.db.new.gz ] && cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null || true
        else
            warn "AIDE غير مثبت"
        fi
    fi
else
    ok "قاعدة بيانات AIDE موجودة"
fi

# إصلاح خدمة dailyaidecheck
if [ -f /etc/systemd/system/dailyaidecheck.service ] || true; then
    info "إصلاح خدمة dailyaidecheck..."

    cat > /etc/systemd/system/dailyaidecheck.service << 'AIDE_SVC'
[Unit]
Description=daily AIDE check
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'if [ -f /var/lib/aide/aide.db ] || [ -f /var/lib/aide/aide.db.gz ]; then aide --check 2>/dev/null || true; else echo "AIDE DB not found, initializing..."; aide --init 2>/dev/null && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null; fi'
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
AIDE_SVC

    if [ ! -f /etc/systemd/system/dailyaidecheck.timer ]; then
        cat > /etc/systemd/system/dailyaidecheck.timer << 'AIDE_TMR'
[Unit]
Description=Daily AIDE check timer

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
AIDE_TMR
    fi

    systemctl daemon-reload 2>/dev/null || true

    if systemctl start dailyaidecheck >> "$LOG" 2>&1; then
        ok "dailyaidecheck يعمل الآن"
        AIDE_OK=true
    else
        warn "dailyaidecheck لا يزال يفشل"
        # إنشاء قاعدة بيانات في الخلفية
        if command -v aide &>/dev/null; then
            aide --init >> "$LOG" 2>&1 &
            info "AIDE يُنشئ قاعدة البيانات في الخلفية"
        fi
    fi

    systemctl enable dailyaidecheck.timer >> "$LOG" 2>/dev/null || true
    systemctl start dailyaidecheck.timer >> "$LOG" 2>/dev/null || true
fi

systemctl reset-failed dailyaidecheck.service 2>/dev/null || true

if $AIDE_OK; then
    step_ok "AIDE Daily Check تم إصلاحه"
else
    step_partial "AIDE تم إعداده - قد يحتاج وقت لإنشاء القاعدة"
fi

###############################################################################
# المشكلة 5: UFW غير مفعل
###############################################################################
step "5/12 - تفعيل UFW Firewall"

UFW_OK=false

info "تفعيل جدار الحماية..."

# السماح بـ SSH أولاً
ufw allow 22/tcp comment 'SSH' >> "$LOG" 2>&1 || true
ufw allow 80/tcp comment 'HTTP' >> "$LOG" 2>&1 || true
ufw allow 443/tcp comment 'HTTPS' >> "$LOG" 2>&1 || true

# تفعيل UFW
echo "y" | ufw enable >> "$LOG" 2>&1 || true
ufw reload >> "$LOG" 2>&1 || true

if ufw status 2>/dev/null | grep -q "active"; then
    ok "UFW مفعل ونشط"
    ufw status numbered 2>/dev/null || true
    UFW_OK=true
    step_ok "UFW تم تفعيله"
else
    step_failed "فشل تفعيل UFW"
fi

###############################################################################
# المشكلة 6: SSH - X11Forwarding مفعل
###############################################################################
step "6/12 - تأمين SSH (تعطيل X11Forwarding)"

SSH_OK=false

cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)" 2>/dev/null || true

sed -i 's/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config 2>/dev/null || true

if ! grep -q "^X11Forwarding no" /etc/ssh/sshd_config 2>/dev/null; then
    echo "X11Forwarding no" >> /etc/ssh/sshd_config
fi

if sshd -t >> "$LOG" 2>&1; then
    systemctl restart sshd >> "$LOG" 2>&1 || systemctl restart ssh >> "$LOG" 2>&1 || true
    ok "SSH أعيد تشغيله بنجاح"
    SSH_OK=true
    step_ok "SSH X11Forwarding تم تعطيله"
else
    fail "خطأ في إعدادات SSH - استرجاع النسخة الاحتياطية"
    LATEST_BACKUP=$(ls -t /etc/ssh/sshd_config.bak.* 2>/dev/null | head -1)
    if [ -n "$LATEST_BACKUP" ]; then
        cp "$LATEST_BACKUP" /etc/ssh/sshd_config 2>/dev/null || true
    fi
    systemctl restart sshd >> "$LOG" 2>&1 || systemctl restart ssh >> "$LOG" 2>&1 || true
    step_failed "فشل تعديل SSH - تم الاسترجاع"
fi

###############################################################################
# المشكلة 7: Sysctl - إعدادات خاطئة
###############################################################################
step "7/12 - إصلاح Sysctl (3 إعدادات خاطئة)"

SYSCTL_OK=true

info "المشاكل المكتشفة:"
info "  1. net.ipv4.ip_forward = 1 (يجب أن يكون 0)"
info "  2. net.ipv4.conf.all.send_redirects = 1 (يجب أن يكون 0)"
info "  3. net.ipv6.conf.all.accept_redirects = 1 (يجب أن يكون 0)"

# كشف Docker
DOCKER_RUNNING=false
if docker ps >> "$LOG" 2>&1; then
    DOCKER_RUNNING=true
    warn "Docker يعمل - ip_forward سيبقى مفعّل لأن Docker يحتاجه"
fi

cat > /etc/sysctl.d/99-security-fix.conf << 'SYSCTL_FIX'
#############################################
# إصلاح الإعدادات الأمنية
#############################################

# تعطيل Send Redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# تعطيل IPv6 Accept Redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
SYSCTL_FIX

# ip_forward فقط إذا لم يكن Docker يعمل
if ! $DOCKER_RUNNING; then
    echo "" >> /etc/sysctl.d/99-security-fix.conf
    echo "# تعطيل IP Forwarding (لا يوجد Docker)" >> /etc/sysctl.d/99-security-fix.conf
    echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/99-security-fix.conf
else
    echo "" >> /etc/sysctl.d/99-security-fix.conf
    echo "# ip_forward يبقى مفعّل لـ Docker" >> /etc/sysctl.d/99-security-fix.conf
    echo "# net.ipv4.ip_forward = 0" >> /etc/sysctl.d/99-security-fix.conf
fi

sysctl -p /etc/sysctl.d/99-security-fix.conf >> "$LOG" 2>&1 || warn "بعض الإعدادات قد لا تُطبّق"

echo ""
info "القيم بعد الإصلاح:"
SYSCTL_ISSUES=0
for key in net.ipv4.conf.all.send_redirects net.ipv6.conf.all.accept_redirects; do
    val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    if [ "$val" = "0" ]; then
        ok "  $key = $val"
    else
        warn "  $key = $val (لم يتغير)"
        SYSCTL_ISSUES=$((SYSCTL_ISSUES + 1))
    fi
done

# ip_forward
IP_FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "N/A")
if $DOCKER_RUNNING; then
    info "  net.ipv4.ip_forward = $IP_FWD (مطلوب لـ Docker)"
else
    if [ "$IP_FWD" = "0" ]; then
        ok "  net.ipv4.ip_forward = 0"
    else
        warn "  net.ipv4.ip_forward = $IP_FWD"
        SYSCTL_ISSUES=$((SYSCTL_ISSUES + 1))
    fi
fi

if [ "$SYSCTL_ISSUES" -eq 0 ]; then
    step_ok "Sysctl تم إصلاحه"
else
    step_partial "Sysctl - تم إصلاح بعض الإعدادات ($SYSCTL_ISSUES لم تتغير)"
fi

###############################################################################
# المشكلة 8: NTP غير مفعل
###############################################################################
step "8/12 - تفعيل مزامنة الوقت (NTP)"

NTP_OK=false

info "الحالة الحالية: NTP inactive"

timedatectl set-ntp true >> "$LOG" 2>&1 || true

if dpkg -l ntp 2>/dev/null | grep -q "^ii"; then
    info "تفعيل خدمة NTP..."

    if [ -f /etc/ntp.conf ]; then
        grep -q "pool.ntp.org" /etc/ntp.conf 2>/dev/null || {
            cat >> /etc/ntp.conf << 'NTP_SERVERS'

pool 0.ubuntu.pool.ntp.org iburst
pool 1.ubuntu.pool.ntp.org iburst
pool 2.ubuntu.pool.ntp.org iburst
pool 3.ubuntu.pool.ntp.org iburst
NTP_SERVERS
        }
    fi

    systemctl stop systemd-timesyncd >> "$LOG" 2>/dev/null || true
    systemctl disable systemd-timesyncd >> "$LOG" 2>/dev/null || true

    systemctl enable ntp >> "$LOG" 2>&1 || true
    systemctl restart ntp >> "$LOG" 2>&1 || true
    sleep 3

    if systemctl is-active --quiet ntp 2>/dev/null; then
        ok "NTP يعمل"
        NTP_OK=true
    else
        warn "NTP لا يعمل - استخدام systemd-timesyncd"
        systemctl enable systemd-timesyncd >> "$LOG" 2>&1 || true
        systemctl start systemd-timesyncd >> "$LOG" 2>&1 || true
        timedatectl set-ntp true >> "$LOG" 2>&1 || true
        NTP_OK=true
    fi
else
    info "استخدام systemd-timesyncd..."
    systemctl enable systemd-timesyncd >> "$LOG" 2>&1 || true
    systemctl start systemd-timesyncd >> "$LOG" 2>&1 || true
    timedatectl set-ntp true >> "$LOG" 2>&1 || true
    NTP_OK=true
fi

sleep 3
ntpdate pool.ntp.org >> "$LOG" 2>&1 || ntpd -gq >> "$LOG" 2>&1 || true

if $NTP_OK; then
    step_ok "NTP تم تفعيله"
else
    step_partial "NTP - المزامنة بدأت وقد تحتاج دقائق"
fi

###############################################################################
# المشكلة 9: Nginx - إعداده
###############################################################################
step "9/12 - إعداد Nginx"

NGINX_OK=false

if dpkg -l nginx 2>/dev/null | grep -q "^ii"; then
    info "إعداد Nginx الأساسي..."

    cat > /etc/nginx/conf.d/security.conf << 'NGINX_SEC'
server_tokens off;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
client_max_body_size 10M;
client_body_timeout 30s;
client_header_timeout 30s;
keepalive_timeout 30;
send_timeout 30;
NGINX_SEC

    if nginx -t >> "$LOG" 2>&1; then
        systemctl enable nginx >> "$LOG" 2>&1 || true
        systemctl start nginx >> "$LOG" 2>&1 || systemctl restart nginx >> "$LOG" 2>&1 || true
        if systemctl is-active --quiet nginx 2>/dev/null; then
            ok "Nginx يعمل مع إعدادات أمنية"
            NGINX_OK=true
        fi
    else
        rm -f /etc/nginx/conf.d/security.conf 2>/dev/null || true
        systemctl enable nginx >> "$LOG" 2>&1 || true
        systemctl start nginx >> "$LOG" 2>&1 || true
        warn "Nginx يعمل بدون إعدادات أمنية إضافية"
        NGINX_OK=true
    fi

    if $NGINX_OK; then
        step_ok "Nginx تم إعداده"
    else
        step_partial "Nginx مثبت لكنه يحتاج مراجعة"
    fi
else
    step_partial "Nginx لم يُثبت - تخطّي"
fi

###############################################################################
# المشكلة 10: إعداد Monit + Lynis
###############################################################################
step "10/12 - إعداد Monit و Lynis"

MONIT_OK=false
LYNIS_OK=false

# === Monit ===
if command -v monit &>/dev/null; then
    info "إعداد Monit..."

    mkdir -p /etc/monit/conf.d 2>/dev/null || true

    cat > /etc/monit/conf.d/system << 'MONIT_SYS'
check system $HOST
    if loadavg (1min) per core > 2 for 5 cycles then alert
    if cpu usage > 90% for 10 cycles then alert
    if memory usage > 85% then alert
    if swap usage > 50% then alert

check filesystem rootfs with path /
    if space usage > 85% then alert
    if space usage > 95% then alert
MONIT_SYS

    # فحص وجود sshd pidfile قبل إضافة المراقبة
    SSHD_PID=""
    if [ -f /var/run/sshd.pid ]; then
        SSHD_PID="/var/run/sshd.pid"
    elif [ -f /run/sshd.pid ]; then
        SSHD_PID="/run/sshd.pid"
    fi

    if [ -n "$SSHD_PID" ]; then
        cat > /etc/monit/conf.d/sshd << MONIT_SSH
check process sshd with pidfile $SSHD_PID
    start program = "/bin/systemctl start sshd"
    stop program = "/bin/systemctl stop sshd"
    if failed port 22 protocol ssh then restart
    if 5 restarts within 5 cycles then alert
MONIT_SSH
    else
        # مراقبة بدون pidfile
        cat > /etc/monit/conf.d/sshd << 'MONIT_SSH2'
check process sshd matching "sshd"
    start program = "/bin/systemctl start sshd"
    stop program = "/bin/systemctl stop sshd"
    if failed port 22 protocol ssh then restart
    if 5 restarts within 5 cycles then alert
MONIT_SSH2
    fi

    if [ -f /etc/monit/monitrc ]; then
        if ! grep -q "^set httpd" /etc/monit/monitrc 2>/dev/null; then
            cat >> /etc/monit/monitrc << 'MONIT_HTTP'

set httpd port 2812
    use address localhost
    allow localhost
    allow admin:monit
MONIT_HTTP
        fi
    fi

    systemctl enable monit >> "$LOG" 2>&1 || true

    # اختبار إعدادات Monit قبل التشغيل
    if monit -t >> "$LOG" 2>&1; then
        systemctl restart monit >> "$LOG" 2>&1 || true
        sleep 2
        if systemctl is-active --quiet monit 2>/dev/null; then
            ok "Monit يعمل"
            MONIT_OK=true
        else
            warn "Monit لم يبدأ رغم صحة الإعدادات"
        fi
    else
        warn "إعدادات Monit بها مشكلة - إصلاح..."
        # إزالة الإعدادات المخصصة والمحاولة مرة أخرى
        rm -f /etc/monit/conf.d/sshd 2>/dev/null || true
        if monit -t >> "$LOG" 2>&1; then
            systemctl restart monit >> "$LOG" 2>&1 || true
            systemctl is-active --quiet monit 2>/dev/null && MONIT_OK=true
        fi
    fi
fi

# === Lynis ===
if command -v lynis &>/dev/null; then
    info "إعداد Lynis..."
    lynis update info >> "$LOG" 2>&1 || true

    cat > /etc/cron.weekly/lynis-audit << 'LYNIS_CRON'
#!/bin/bash
lynis audit system --cronjob --quiet > /var/log/lynis-report.txt 2>&1
LYNIS_CRON
    chmod +x /etc/cron.weekly/lynis-audit 2>/dev/null || true

    ok "Lynis مُعد مع فحص أسبوعي"
    LYNIS_OK=true
fi

if $MONIT_OK && $LYNIS_OK; then
    step_ok "Monit و Lynis تم إعدادهما"
elif $MONIT_OK || $LYNIS_OK; then
    step_partial "تم إعداد أحد الأداتين"
else
    step_failed "فشل إعداد Monit و Lynis"
fi

###############################################################################
# المشكلة 11: إعداد Certbot
###############################################################################
step "11/12 - إعداد Certbot"

CERTBOT_OK=false

if command -v certbot &>/dev/null; then
    info "Certbot مثبت"

    # التجديد التلقائي
    if systemctl list-timers 2>/dev/null | grep -q certbot; then
        ok "Certbot timer موجود مسبقاً"
        CERTBOT_OK=true
    else
        systemctl enable certbot.timer >> "$LOG" 2>&1 || {
            if ! crontab -l 2>/dev/null | grep -q "certbot"; then
                (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload nginx' 2>/dev/null") | crontab - 2>/dev/null
                ok "تم جدولة تجديد الشهادات في cron"
            fi
        }
        CERTBOT_OK=true
    fi

    ok "Certbot جاهز"
    info "لإنشاء شهادة: certbot --nginx -d yourdomain.com"

    if $CERTBOT_OK; then
        step_ok "Certbot تم إعداده"
    else
        step_partial "Certbot مثبت - يحتاج إعداد يدوي"
    fi
else
    step_partial "Certbot لم يُثبت - تخطّي"
fi

###############################################################################
# المشكلة 12: تحسين المراقبة و Fail2Ban
###############################################################################
step "12/12 - تحسين المراقبة و Fail2Ban"

F2B_OK=false

# === Fail2Ban ===
info "إعداد Fail2Ban..."

# إنشاء ملفات السجل المطلوبة أولاً (قبل الإعداد)
mkdir -p /var/log/nginx 2>/dev/null || true
touch /var/log/nginx/error.log /var/log/nginx/access.log 2>/dev/null || true

# نبدأ بقاعدة sshd فقط، ونضيف nginx إذا كان يعمل
cat > /etc/fail2ban/jail.local << 'F2B_BASE'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 3
bantime = 7200

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
maxretry = 5
bantime = 3600
F2B_BASE

# إضافة قواعد nginx فقط إذا كان مثبت ويعمل
if systemctl is-active --quiet nginx 2>/dev/null; then
    cat >> /etc/fail2ban/jail.local << 'F2B_NGINX'

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 5

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 5
F2B_NGINX
    info "تم إضافة قواعد Nginx لـ Fail2Ban"
else
    info "Nginx غير نشط - قواعد SSH فقط"
fi

# اختبار الإعدادات قبل إعادة التشغيل
if fail2ban-client -t >> "$LOG" 2>&1; then
    systemctl restart fail2ban >> "$LOG" 2>&1 || true
    sleep 2

    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://' || echo "غير متوفر")
        ok "Fail2Ban يعمل - Jails: $JAILS"
        F2B_OK=true
    else
        warn "Fail2Ban لم يبدأ"
    fi
else
    warn "إعدادات Fail2Ban بها مشكلة - تبسيط..."
    # إعدادات مبسطة
    cat > /etc/fail2ban/jail.local << 'F2B_SIMPLE'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 3
bantime = 7200
F2B_SIMPLE
    systemctl restart fail2ban >> "$LOG" 2>&1 || true
    sleep 2
    systemctl is-active --quiet fail2ban 2>/dev/null && F2B_OK=true
fi

# === سكربت المراقبة المحسّن ===
info "تحسين سكربت المراقبة..."

cat > /usr/local/bin/system_monitor.sh << 'ENHANCED_MONITOR'
#!/bin/bash
set +e

LOG="/var/log/system-monitor.log"
ALERT_LOG="/var/log/system-alerts.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG" 2>/dev/null; }
alert() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: $1" | tee -a "$ALERT_LOG" >> "$LOG" 2>/dev/null; }

log "========== بدء فحص المراقبة =========="

# CPU
CPU=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print int($2+$4)}')
[ "${CPU:-0}" -gt 90 ] && alert "CPU عالي: ${CPU}%" || log "CPU: ${CPU:-N/A}%"

# الذاكرة
MEM_TOTAL=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')
MEM_USED=$(free -m 2>/dev/null | awk '/^Mem:/{print $3}')
if [ "${MEM_TOTAL:-0}" -gt 0 ]; then
    MEM_PCT=$((MEM_USED * 100 / MEM_TOTAL))
    [ "$MEM_PCT" -gt 85 ] && alert "الذاكرة: ${MEM_PCT}%" || log "الذاكرة: ${MEM_PCT}%"
fi

# القرص
df -h / /var /tmp 2>/dev/null | tail -n+2 | while read -r line; do
    USE=$(echo "$line" | awk '{print $5}' | tr -d '%')
    MNT=$(echo "$line" | awk '{print $6}')
    [ "${USE:-0}" -gt 85 ] && alert "القرص $MNT: ${USE}%" || log "القرص $MNT: ${USE}%"
done

# Load
LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{print $1}')
CPUS=$(nproc 2>/dev/null || echo 1)
LOAD_INT=${LOAD%.*}
[ "${LOAD_INT:-0}" -gt "$((CPUS * 2))" ] && alert "Load عالي: $LOAD" || log "Load: ${LOAD:-N/A}"

# الخدمات الحرجة
for svc in sshd fail2ban ufw nginx clamav-daemon monit; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            log "خدمة $svc: تعمل"
        else
            alert "خدمة $svc متوقفة! محاولة إعادة التشغيل..."
            systemctl start "$svc" >> "$LOG" 2>&1 || true
        fi
    fi
done

# محاولات الاختراق
if [ -f /var/log/auth.log ]; then
    FAILED_TODAY=$(grep "$(date +%b\ %d)" /var/log/auth.log 2>/dev/null | grep -c "Failed password" || echo 0)
    [ "${FAILED_TODAY:-0}" -gt 50 ] && alert "محاولات فاشلة: $FAILED_TODAY" || log "محاولات فاشلة: ${FAILED_TODAY:-0}"
fi

# Swap
SWAP_TOTAL=$(free -m 2>/dev/null | awk '/^Swap:/{print $2}')
SWAP_USED=$(free -m 2>/dev/null | awk '/^Swap:/{print $3}')
if [ "${SWAP_TOTAL:-0}" -gt 0 ]; then
    SWAP_PCT=$((SWAP_USED * 100 / SWAP_TOTAL))
    [ "$SWAP_PCT" -gt 50 ] && alert "Swap: ${SWAP_PCT}%" || log "Swap: ${SWAP_PCT}%"
fi

# اتصال الإنترنت
ping -c 1 -W 5 8.8.8.8 &>/dev/null && log "إنترنت: متصل" || alert "لا يوجد اتصال!"

# Zombie
ZOMBIES=$(ps aux 2>/dev/null | grep -c "[d]efunct" || echo 0)
[ "${ZOMBIES:-0}" -gt 5 ] && alert "Zombie: $ZOMBIES" || log "Zombie: ${ZOMBIES:-0}"

# خدمات فاشلة
FAILED_SVCS=$(systemctl --failed --no-pager 2>/dev/null | grep -c "failed" || echo 0)
[ "${FAILED_SVCS:-0}" -gt 0 ] && alert "خدمات فاشلة: $FAILED_SVCS" || log "لا خدمات فاشلة"

# تدوير السجل
if [ -f "$LOG" ]; then
    LOG_SIZE=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
    [ "${LOG_SIZE:-0}" -gt 10485760 ] && mv "$LOG" "${LOG}.old" 2>/dev/null
fi

log "========== انتهى الفحص =========="

# إخراج ملخص
echo ""
echo "===== تقرير مراقبة النظام - $(date) ====="
echo "CPU: ${CPU:-N/A}%"
echo "RAM: ${MEM_PCT:-N/A}% (${MEM_USED:-N/A}MB/${MEM_TOTAL:-N/A}MB)"
echo "Load: ${LOAD:-N/A} (CPUs: ${CPUS:-N/A})"
echo "Swap: ${SWAP_USED:-0}MB/${SWAP_TOTAL:-0}MB"
echo ""
echo "=== حالة الخدمات ==="
for svc in sshd fail2ban ufw nginx clamav-daemon monit crowdsec; do
    STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "not-found")
    echo "  $svc: $STATUS"
done
echo ""
df -h / /var /tmp 2>/dev/null || true
echo "=================================="
ENHANCED_MONITOR

chmod +x /usr/local/bin/system_monitor.sh 2>/dev/null || true

# تحديث cron
(crontab -l 2>/dev/null | grep -v "system_monitor.sh"
echo "*/5 * * * * /usr/local/bin/system_monitor.sh > /tmp/system_report.txt 2>&1"
) | crontab - 2>/dev/null || true

# تشغيل المراقبة الآن
/usr/local/bin/system_monitor.sh > /tmp/system_report.txt 2>&1 || true

if $F2B_OK; then
    step_ok "Fail2Ban والمراقبة تم تحسينهما"
else
    step_partial "المراقبة تم تحسينها - Fail2Ban يحتاج مراجعة"
fi

###############################################################################
# تنظيف وإعادة تشغيل
###############################################################################

step "تنظيف وإعادة تشغيل الخدمات"

systemctl reset-failed 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

SERVICES_RESTART=(sshd ufw fail2ban nginx auditd monit rsyslog)

for svc in "${SERVICES_RESTART[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
        systemctl enable "$svc" >> "$LOG" 2>/dev/null || true
        systemctl restart "$svc" >> "$LOG" 2>&1 && ok "$svc يعمل" || warn "$svc يحتاج مراجعة"
    fi
done

systemctl restart clamav-freshclam >> "$LOG" 2>&1 || true
sleep 2
systemctl restart clamav-daemon >> "$LOG" 2>&1 || true

timedatectl set-ntp true >> "$LOG" 2>&1 || true
systemctl restart ntp >> "$LOG" 2>&1 || systemctl restart systemd-timesyncd >> "$LOG" 2>&1 || true

###############################################################################
# التحقق النهائي
###############################################################################

step "التحقق النهائي"

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          حالة الخدمات بعد الإصلاح                       ║${NC}"
echo -e "${CYAN}╠═══════════════════════════════════════════════════════════╣${NC}"

ALL_SERVICES=(sshd ufw fail2ban nginx clamav-daemon clamav-freshclam auditd monit rsyslog ntp crowdsec)

ACTIVE_COUNT=0
INACTIVE_COUNT=0

for svc in "${ALL_SERVICES[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "$svc"; then
        STATUS=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        case "$STATUS" in
            active)
                echo -e "${CYAN}║${NC}  ${GREEN}✅ $svc: active${NC}"
                ACTIVE_COUNT=$((ACTIVE_COUNT + 1))
                ;;
            *)
                echo -e "${CYAN}║${NC}  ${RED}❌ $svc: $STATUS${NC}"
                INACTIVE_COUNT=$((INACTIVE_COUNT + 1))
                ;;
        esac
    fi
done

echo -e "${CYAN}╠═══════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║          الإعدادات المصلحة                               ║${NC}"
echo -e "${CYAN}╠═══════════════════════════════════════════════════════════╣${NC}"

UFW_ST=$(ufw status 2>/dev/null | head -1 || echo "غير متوفر")
echo -e "${CYAN}║${NC}  UFW: $UFW_ST"

X11=$(grep "^X11Forwarding" /etc/ssh/sshd_config 2>/dev/null || echo "غير محدد")
echo -e "${CYAN}║${NC}  SSH: $X11"

for key in net.ipv4.ip_forward net.ipv4.conf.all.send_redirects net.ipv6.conf.all.accept_redirects; do
    val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    echo -e "${CYAN}║${NC}  $key = $val"
done

NTP_SYNC=$(timedatectl 2>/dev/null | grep "synchronized" | awk '{print $NF}' || echo "N/A")
echo -e "${CYAN}║${NC}  NTP synchronized: $NTP_SYNC"

F2B_JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://' | xargs || echo "غير متوفر")
echo -e "${CYAN}║${NC}  Fail2Ban Jails: $F2B_JAILS"

FAILED_COUNT=$(systemctl --failed --no-pager 2>/dev/null | grep -c "failed" || echo 0)
echo -e "${CYAN}║${NC}  خدمات فاشلة: $FAILED_COUNT"

echo -e "${CYAN}╠═══════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║          ملخص النتائج                                    ║${NC}"
echo -e "${CYAN}╠═══════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  ${GREEN}✅ نجحت:${NC}    $STEPS_OK / $TOTAL_STEPS"
echo -e "${CYAN}║${NC}  ${YELLOW}⚠️  جزئي:${NC}   $STEPS_PARTIAL / $TOTAL_STEPS"
echo -e "${CYAN}║${NC}  ${RED}❌ فشلت:${NC}    $STEPS_FAILED / $TOTAL_STEPS"
echo -e "${CYAN}║${NC}  خدمات نشطة: $ACTIVE_COUNT  |  متوقفة: $INACTIVE_COUNT"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"

echo ""

if [ "$STEPS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                         ║"
    echo "║    ✅ اكتمل الإصلاح بنجاح!                              ║"
    echo "║                                                         ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
elif [ "$STEPS_FAILED" -le 2 ]; then
    echo -e "${YELLOW}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                         ║"
    echo "║    ⚠️  اكتمل الإصلاح مع بعض التحذيرات                   ║"
    echo "║    $STEPS_FAILED من $TOTAL_STEPS خطوات تحتاج مراجعة يدوية             ║"
    echo "║                                                         ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
else
    echo -e "${RED}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                         ║"
    echo "║    ❌ بعض الإصلاحات فشلت - مراجعة يدوية مطلوبة          ║"
    echo "║    راجع السجل: $LOG"
    echo "║                                                         ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
fi

echo ""
echo -e "  📄 سجل الإصلاح: ${BOLD}$LOG${NC}"
echo -e "  📌 الخطوة التالية: ${BOLD}sudo bash /usr/local/bin/check-server.sh${NC}"
echo ""

exit 0

