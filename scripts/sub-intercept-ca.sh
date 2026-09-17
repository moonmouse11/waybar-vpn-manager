#!/usr/bin/env bash
# Dev tool: generate a local CA + server certificate for intercepting the
# Happ GUI subscription request (to learn the exact request headers/UA the
# app sends; the remote serves a stub to plain curl).
#
# Usage:
#   bash scripts/sub-intercept-ca.sh xskx.artemida.live
# then follow the printed sudo steps, add the hosts entry, run
# scripts/sub-intercept-serve.py and press «update subscription» in Happ.
set -euo pipefail

DOMAIN="${1:-xskx.artemida.live}"
WORKDIR="/tmp/happ-intercept"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

if [[ ! -f ca.key ]]; then
    openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt \
        -days 30 -nodes -subj "/CN=happ-intercept-local" 2>/dev/null
fi

cat > san.ext <<EOF
subjectAltName = DNS:$DOMAIN
EOF

openssl req -newkey rsa:2048 -keyout server.key -out server.csr \
    -nodes -subj "/CN=$DOMAIN" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 7 -extfile san.ext 2>/dev/null

echo "generated in $WORKDIR:"
ls -la ca.crt server.crt server.key
echo ""
echo "== sudo steps =="
echo "1) trust the local CA (so the GUI accepts our certificate):"
echo "   sudo cp $WORKDIR/ca.crt /etc/ca-certificates/trust-source/anchors/happ-intercept.crt"
echo "   sudo trust extract-compat"
echo "2) redirect the subscription host to localhost:"
echo "   echo '127.0.0.1 $DOMAIN' | sudo tee -a /etc/hosts"
echo "3) run the capture server (needs root for port 443):"
echo "   sudo python3 scripts/sub-intercept-serve.py $DOMAIN"
echo "4) in Happ: open the subscription settings and press update (or restart the app)"
echo "5) the captured request lands in $WORKDIR/request.txt"
echo "6) cleanup afterwards:"
echo "   sudo sed -i '/$DOMAIN/d' /etc/hosts"
echo "   sudo rm /etc/ca-certificates/trust-source/anchors/happ-intercept.crt && sudo trust extract-compat"
