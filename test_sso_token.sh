#!/bin/bash

# Script untuk test SSO token exchange
# Usage: ./test_sso_token.sh <AUTHORIZATION_CODE>

if [ -z "$1" ]; then
    echo "❌ Error: Authorization code required"
    echo "Usage: ./test_sso_token.sh <AUTHORIZATION_CODE>"
    echo ""
    echo "Cara mendapatkan authorization code:"
    echo "1. Buka http://localhost:8070/login"
    echo "2. Klik 'Login dengan SSO'"
    echo "3. Login di SSO"
    echo "4. Copy authorization code dari URL callback"
    exit 1
fi

CODE=$1
SSO_SERVER=${SSO_SERVER_URL:-http://localhost:8080}
REDIRECT_URI=${SSO_REDIRECT_URI:-http://localhost:8070/api/callback}
CLIENT_ID=${SSO_CLIENT_ID:-client-dinas-pendidikan}

echo "🧪 Testing SSO Token Exchange"
echo "================================"
echo "SSO Server: $SSO_SERVER"
echo "Redirect URI: $REDIRECT_URI"
echo "Client ID: $CLIENT_ID"
echo "Code: ${CODE:0:20}..."
echo ""
echo "📤 Sending request..."
echo ""

curl -X POST "$SSO_SERVER/api/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" \
  -w "\n\nHTTP Status: %{http_code}\n" \
  -v 2>&1 | grep -E "(< |> |\{|\"access_token|\"error)"

echo ""
echo "✅ Test completed!"

