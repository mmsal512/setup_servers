#!/bin/bash
#===============================================================================
# check_webhook.sh - سكربت التحقق من عمل Webhook
# الرابط: https://example.com/webhook/alerts
#===============================================================================

# ألوان للطباعة
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# المتغيرات
WEBHOOK_URL="https://example.com/webhook/alerts"
LOG_FILE="/var/log/webhook_check.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

#===============================================================================
# الدوال
#===============================================================================

print_header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║       🔍 فحص Webhook - example.com                   ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  URL: ${WEBHOOK_URL}  ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n"
}

log_result() {
    echo "[$TIMESTAMP] $1" >> "$LOG_FILE" 2>/dev/null
}

print_pass() {
    echo -e "  ${GREEN}✅ [PASS]${NC} $1"
    log_result "[PASS] $1"
}

print_fail() {
    echo -e "  ${RED}❌ [FAIL]${NC} $1"
    log_result "[FAIL] $1"
}

print_warn() {
    echo -e "  ${YELLOW}⚠️  [WARN]${NC} $1"
    log_result "[WARN] $1"
}

print_info() {
    echo -e "  ${BLUE}ℹ️  [INFO]${NC} $1"
}

#===============================================================================
# 1. فحص DNS
#===============================================================================
check_dns() {
    echo -e "${YELLOW}━━━ 1. فحص DNS Resolution ━━━${NC}"

    DNS_RESULT=$(dig +short example.com 2>/dev/null)

    if [ -z "$DNS_RESULT" ]; then
        # جرب nslookup كبديل
        DNS_RESULT=$(nslookup example.com 2>/dev/null | grep -A1 "Name:" | grep "Address" | awk '{print $2}')
    fi

    if [ -n "$DNS_RESULT" ]; then
        print_pass "DNS يعمل - IP: ${DNS_RESULT}"
        SERVER_IP="$DNS_RESULT"
    else
        print_fail "فشل في حل DNS لـ example.com"
        return 1
    fi
}

#===============================================================================
# 2. فحص الاتصال بالسيرفر
#===============================================================================
check_connectivity() {
    echo -e "\n${YELLOW}━━━ 2. فحص الاتصال بالسيرفر ━━━${NC}"

    # فحص ping
    if ping -c 2 -W 5 example.com &>/dev/null; then
        print_pass "السيرفر يستجيب لـ ping"
    else
        print_warn "السيرفر لا يستجيب لـ ping (قد يكون ICMP محجوب)"
    fi

    # فحص البورت 443 (HTTPS)
    if timeout 5 bash -c 'echo > /dev/tcp/example.com/443' 2>/dev/null; then
        print_pass "البورت 443 (HTTPS) مفتوح"
    else
        print_fail "البورت 443 (HTTPS) مغلق أو غير متاح"
    fi

    # فحص البورت 80 (HTTP)
    if timeout 5 bash -c 'echo > /dev/tcp/example.com/80' 2>/dev/null; then
        print_pass "البورت 80 (HTTP) مفتوح"
    else
        print_warn "البورت 80 (HTTP) مغلق"
    fi
}

#===============================================================================
# 3. فحص شهادة SSL
#===============================================================================
check_ssl() {
    echo -e "\n${YELLOW}━━━ 3. فحص شهادة SSL ━━━${NC}"

    SSL_INFO=$(echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null)

    if [ $? -eq 0 ]; then
        # استخراج تاريخ انتهاء الشهادة
        EXPIRY=$(echo "$SSL_INFO" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

        if [ -n "$EXPIRY" ]; then
            EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
            NOW_EPOCH=$(date +%s)
            DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

            print_pass "شهادة SSL صالحة - تنتهي في: ${EXPIRY}"

            if [ "$DAYS_LEFT" -lt 30 ]; then
                print_warn "الشهادة تنتهي خلال ${DAYS_LEFT} يوم - يجب التجديد!"
            else
                print_info "متبقي ${DAYS_LEFT} يوم على انتهاء الشهادة"
            fi
        fi

        # التحقق من اسم الدومين في الشهادة
        CN=$(echo "$SSL_INFO" | openssl x509 -noout -subject 2>/dev/null | grep -oP 'CN\s*=\s*\K.*')
        print_info "الشهادة صادرة لـ: ${CN}"
    else
        print_fail "فشل في التحقق من شهادة SSL"
    fi
}

#===============================================================================
# 4. فحص HTTP GET على الـ Webhook
#===============================================================================
check_webhook_get() {
    echo -e "\n${YELLOW}━━━ 4. فحص HTTP GET على Webhook ━━━${NC}"

    RESPONSE=$(curl -s -o /tmp/webhook_response.txt -w "%{http_code}|%{time_total}|%{redirect_url}" \
        -A "WebhookChecker/1.0" \
        --max-time 15 \
        --connect-timeout 10 \
        "${WEBHOOK_URL}" 2>/dev/null)

    HTTP_CODE=$(echo "$RESPONSE" | cut -d'|' -f1)
    TIME_TOTAL=$(echo "$RESPONSE" | cut -d'|' -f2)
    REDIRECT_URL=$(echo "$RESPONSE" | cut -d'|' -f3)

    print_info "HTTP Status Code: ${HTTP_CODE}"
    print_info "وقت الاستجابة: ${TIME_TOTAL} ثانية"

    case "$HTTP_CODE" in
        200)
            print_pass "Webhook يستجيب بنجاح (200 OK)"
            ;;
        201|202|204)
            print_pass "Webhook يستجيب بنجاح (${HTTP_CODE})"
            ;;
        301|302|307|308)
            print_warn "Webhook يعيد التوجيه (${HTTP_CODE}) إلى: ${REDIRECT_URL}"
            ;;
        401|403)
            print_warn "Webhook يتطلب مصادقة (${HTTP_CODE}) - هذا طبيعي إذا كان محمي"
            ;;
        404)
            print_fail "Webhook غير موجود (404) - تحقق من المسار /webhook/alerts"
            ;;
        405)
            print_pass "Webhook موجود لكن لا يقبل GET (405) - قد يقبل POST فقط (طبيعي)"
            ;;
        500|502|503)
            print_fail "خطأ في السيرفر (${HTTP_CODE})"
            ;;
        000)
            print_fail "لا يوجد استجابة - السيرفر غير متاح"
            ;;
        *)
            print_warn "كود استجابة غير متوقع: ${HTTP_CODE}"
            ;;
    esac

    # عرض محتوى الاستجابة (أول 200 حرف)
    if [ -f /tmp/webhook_response.txt ]; then
        BODY=$(head -c 200 /tmp/webhook_response.txt 2>/dev/null)
        if [ -n "$BODY" ]; then
            print_info "محتوى الاستجابة (أول 200 حرف):"
            echo -e "         ${BODY}"
        fi
    fi
}

#===============================================================================
# 5. فحص HTTP POST على الـ Webhook (الاختبار الحقيقي)
#===============================================================================
check_webhook_post() {
    echo -e "\n${YELLOW}━━━ 5. فحص HTTP POST على Webhook (اختبار حقيقي) ━━━${NC}"

    # بيانات اختبار تشبه Alertmanager/Prometheus
    TEST_PAYLOAD='{
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "WebhookTest",
                    "severity": "info",
                    "instance": "test-check-script",
                    "job": "webhook_verification"
                },
                "annotations": {
                    "summary": "اختبار تحقق من عمل Webhook",
                    "description": "هذا تنبيه اختباري للتحقق من عمل Webhook - يمكن تجاهله"
                },
                "startsAt": "'$(date -u +%Y-%m-%dT%H:%M:%S.000Z)'",
                "generatorURL": "http://localhost:9090/graph"
            }
        ],
        "groupLabels": {"alertname": "WebhookTest"},
        "commonLabels": {"alertname": "WebhookTest", "severity": "info"},
        "externalURL": "http://localhost:9093",
        "version": "4",
        "receiver": "webhook-test",
        "groupKey": "{}:{alertname=\"WebhookTest\"}"
    }'

    # إرسال POST
    POST_RESPONSE=$(curl -s -o /tmp/webhook_post_response.txt -w "%{http_code}|%{time_total}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "User-Agent: WebhookChecker/1.0" \
        --max-time 15 \
        --connect-timeout 10 \
        -d "${TEST_PAYLOAD}" \
        "${WEBHOOK_URL}" 2>/dev/null)

    POST_CODE=$(echo "$POST_RESPONSE" | cut -d'|' -f1)
    POST_TIME=$(echo "$POST_RESPONSE" | cut -d'|' -f2)

    print_info "HTTP Status Code: ${POST_CODE}"
    print_info "وقت الاستجابة: ${POST_TIME} ثانية"

    case "$POST_CODE" in
        200|201|202|204)
            print_pass "🎉 Webhook يقبل POST بنجاح (${POST_CODE}) - يعمل بشكل صحيح!"
            ;;
        400)
            print_warn "Webhook يرفض البيانات (400) - قد يحتاج صيغة مختلفة"
            ;;
        401|403)
            print_warn "Webhook يتطلب مصادقة (${POST_CODE})"
            ;;
        404)
            print_fail "المسار /webhook/alerts غير موجود (404)"
            ;;
        405)
            print_fail "Webhook لا يقبل POST (405)"
            ;;
        500|502|503)
            print_fail "خطأ في السيرفر عند معالجة POST (${POST_CODE})"
            ;;
        000)
            print_fail "لا يوجد استجابة للـ POST"
            ;;
        *)
            print_warn "كود استجابة غير متوقع: ${POST_CODE}"
            ;;
    esac

    # عرض استجابة POST
    if [ -f /tmp/webhook_post_response.txt ]; then
        POST_BODY=$(head -c 300 /tmp/webhook_post_response.txt 2>/dev/null)
        if [ -n "$POST_BODY" ]; then
            print_info "استجابة POST:"
            echo -e "         ${POST_BODY}"
        fi
    fi
}

#===============================================================================
# 6. فحص الـ Headers
#===============================================================================
check_headers() {
    echo -e "\n${YELLOW}━━━ 6. فحص Response Headers ━━━${NC}"

    HEADERS=$(curl -s -I --max-time 10 "${WEBHOOK_URL}" 2>/dev/null)

    if [ -n "$HEADERS" ]; then
        print_info "Headers المستلمة:"
        echo "$HEADERS" | while IFS= read -r line; do
            line=$(echo "$line" | tr -d '\r')
            [ -n "$line" ] && echo -e "         ${line}"
        done

        # التحقق من headers مهمة
        if echo "$HEADERS" | grep -qi "server:.*nginx"; then
            print_info "السيرفر: Nginx"
        elif echo "$HEADERS" | grep -qi "server:.*apache"; then
            print_info "السيرفر: Apache"
        fi

        # التحقق من Content-Type
        if echo "$HEADERS" | grep -qi "content-type:.*json"; then
            print_pass "يرد بـ JSON"
        fi
    else
        print_warn "لم يتم استلام headers"
    fi
}

#===============================================================================
# 7. فحص الخدمات المحلية (إذا كان السكربت يعمل على نفس السيرفر)
#===============================================================================
check_local_services() {
    echo -e "\n${YELLOW}━━━ 7. فحص الخدمات المحلية (إذا كنت على السيرفر) ━━━${NC}"

    # التحقق من Nginx
    if command -v nginx &>/dev/null; then
        if systemctl is-active --quiet nginx 2>/dev/null; then
            print_pass "Nginx يعمل"
        else
            print_fail "Nginx متوقف!"
            print_info "شغّل: sudo systemctl start nginx"
        fi

        # التحقق من إعدادات Nginx للـ webhook
        if nginx -T 2>/dev/null | grep -q "webhook/alerts"; then
            print_pass "إعدادات webhook موجودة في Nginx"
        elif nginx -T 2>/dev/null | grep -q "webhook"; then
            print_pass "إعدادات webhook موجودة في Nginx (مسار عام)"
        else
            print_warn "لم يتم العثور على إعدادات webhook في Nginx"
        fi
    else
        print_info "Nginx غير مثبت على هذا الجهاز"
    fi

    # التحقق من Alertmanager
    if systemctl is-active --quiet alertmanager 2>/dev/null; then
        print_pass "Alertmanager يعمل"
    elif pgrep -x alertmanager &>/dev/null; then
        print_pass "Alertmanager يعمل (كعملية)"
    else
        print_info "Alertmanager غير موجود أو متوقف"
    fi

    # التحقق من أن هناك خدمة تستمع على البورت المحلي
    WEBHOOK_PORTS=$(ss -tlnp 2>/dev/null | grep -E ':(8080|9093|5000|3000|9090)' | head -5)
    if [ -n "$WEBHOOK_PORTS" ]; then
        print_info "خدمات مستمعة على بورتات شائعة:"
        echo "$WEBHOOK_PORTS" | while IFS= read -r line; do
            echo -e "         ${line}"
        done
    fi
}

#===============================================================================
# 8. فحص Alertmanager config
#===============================================================================
check_alertmanager_config() {
    echo -e "\n${YELLOW}━━━ 8. فحص إعدادات Alertmanager ━━━${NC}"

    # البحث عن ملف الإعدادات
    CONFIG_FILES=(
        "/etc/alertmanager/alertmanager.yml"
        "/opt/alertmanager/alertmanager.yml"
        "/etc/prometheus/alertmanager.yml"
        "$HOME/alertmanager/alertmanager.yml"
    )

    FOUND_CONFIG=""
    for cfg in "${CONFIG_FILES[@]}"; do
        if [ -f "$cfg" ]; then
            FOUND_CONFIG="$cfg"
            break
        fi
    done

    if [ -n "$FOUND_CONFIG" ]; then
        print_pass "ملف إعدادات Alertmanager موجود: ${FOUND_CONFIG}"

        # البحث عن webhook_configs
        if grep -q "webhook_configs" "$FOUND_CONFIG" 2>/dev/null; then
            print_pass "webhook_configs موجود في الإعدادات"

            # البحث عن URL المحدد
            if grep -q "example.com/webhook/alerts" "$FOUND_CONFIG" 2>/dev/null; then
                print_pass "🎯 URL الـ Webhook صحيح: ${WEBHOOK_URL}"
            elif grep -q "webhook" "$FOUND_CONFIG" 2>/dev/null; then
                FOUND_URL=$(grep -A2 "webhook_configs" "$FOUND_CONFIG" | grep "url:" | head -1)
                print_warn "URL مختلف موجود: ${FOUND_URL}"
                print_info "المتوقع: ${WEBHOOK_URL}"
            fi
        else
            print_fail "webhook_configs غير موجود في إعدادات Alertmanager!"
            print_info "أضف التالي في alertmanager.yml:"
            echo -e "         receivers:"
            echo -e "           - name: 'webhook'"
            echo -e "             webhook_configs:"
            echo -e "               - url: '${WEBHOOK_URL}'"
        fi
    else
        print_info "لم يتم العثور على ملف إعدادات Alertmanager"
    fi
}

#===============================================================================
# 9. ملخص النتائج
#===============================================================================
print_summary() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    📊 ملخص الفحص                        ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  🔗 URL: ${WEBHOOK_URL}"
    echo -e "${CYAN}║${NC}  🕐 وقت الفحص: ${TIMESTAMP}"
    echo -e "${CYAN}║${NC}"

    if [ -f /tmp/webhook_post_response.txt ]; then
        POST_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            --max-time 10 \
            -d '{"test": true}' \
            "${WEBHOOK_URL}" 2>/dev/null)

        if [[ "$POST_STATUS" =~ ^(200|201|202|204)$ ]]; then
            echo -e "${CYAN}║${NC}  ${GREEN}🟢 الحالة النهائية: Webhook يعمل بنجاح!${NC}"
        elif [[ "$POST_STATUS" =~ ^(401|403)$ ]]; then
            echo -e "${CYAN}║${NC}  ${YELLOW}🟡 الحالة النهائية: Webhook موجود لكن يحتاج مصادقة${NC}"
        elif [[ "$POST_STATUS" =~ ^(404)$ ]]; then
            echo -e "${CYAN}║${NC}  ${RED}🔴 الحالة النهائية: المسار غير موجود${NC}"
        elif [[ "$POST_STATUS" =~ ^(000)$ ]]; then
            echo -e "${CYAN}║${NC}  ${RED}🔴 الحالة النهائية: السيرفر غير متاح${NC}"
        else
            echo -e "${CYAN}║${NC}  ${YELLOW}🟡 الحالة النهائية: استجابة غير متوقعة (${POST_STATUS})${NC}"
        fi
    fi

    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
}

#===============================================================================
# التنفيذ الرئيسي
#===============================================================================
main() {
    print_header

    check_dns
    check_connectivity
    check_ssl
    check_webhook_get
    check_webhook_post
    check_headers
    check_local_services
    check_alertmanager_config
    print_summary

    # تنظيف الملفات المؤقتة
    rm -f /tmp/webhook_response.txt /tmp/webhook_post_response.txt 2>/dev/null

    echo -e "\n${BLUE}📝 تم حفظ النتائج في: ${LOG_FILE}${NC}\n"
}

# تشغيل
main "$@"