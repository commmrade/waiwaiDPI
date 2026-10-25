#!/usr/bin/env bash
# Делает N HTTPS-запросов к каждому домену и выводит статистику.

allowed_hosts=(
    "patriotvepen.me"
    "soundcloud.com"
    "linkedin.com"
    "instagram.com"
)

N=${N:-50}            # число запросов на домен
TIMEOUT=${TIMEOUT:-10} # таймаут одного запроса, сек

for host in "${allowed_hosts[@]}"; do
    ok=0
    fail=0
    total_time=0

    echo "== $host =="
    for i in $(seq 1 "$N"); do
        out=$(curl -sS -o /dev/null -m "$TIMEOUT" \
            -w '%{http_code} %{time_total}' "https://$host" 2>/tmp/curl_err)
        rc=$?

        if [ $rc -eq 0 ]; then
            code=${out% *}
            t=${out#* }
            ok=$((ok + 1))
            total_time=$(awk -v a="$total_time" -v b="$t" 'BEGIN{print a+b}')
            echo "[$i/$N] HTTP $code (${t}s)"
        else
            fail=$((fail + 1))
            echo "[$i/$N] FAIL curl rc=$rc: $(tr -d '\n' < /tmp/curl_err)"
        fi
    done

    avg="n/a"
    [ "$ok" -gt 0 ] && avg=$(awk -v a="$total_time" -v n="$ok" 'BEGIN{printf "%.3f", a/n}')
    echo "-- $host: ok=$ok fail=$fail avg_time=${avg}s"
    echo
done

rm -f /tmp/curl_err
