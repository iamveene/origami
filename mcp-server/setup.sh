#!/bin/bash
# Origami MCP Server — Setup Script
# Installs dependencies, configures Claude Code, and shows status.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MCP_SERVER_DIR="$SCRIPT_DIR"

echo "=== Origami MCP Server Setup ==="
echo ""

# 1. Install dependencies
echo "[1/3] Installing Node.js dependencies..."
cd "$MCP_SERVER_DIR"
npm install --production
echo "     Done."
echo ""

# 2. Configure Claude Code MCP settings
echo "[2/3] Configuring Claude Code..."

CLAUDE_CONFIG_DIR="$HOME/.claude"
CLAUDE_CONFIG="$CLAUDE_CONFIG_DIR/settings.json"

# Create config directory if it doesn't exist
mkdir -p "$CLAUDE_CONFIG_DIR"

# If settings.json doesn't exist, create it
if [ ! -f "$CLAUDE_CONFIG" ]; then
  echo '{}' > "$CLAUDE_CONFIG"
fi

# Add MCP server configuration using Node.js to safely merge JSON
node -e "
const fs = require('fs');
const path = '$CLAUDE_CONFIG';
let config = {};
try { config = JSON.parse(fs.readFileSync(path, 'utf8')); } catch (e) {}

if (!config.mcpServers) config.mcpServers = {};

config.mcpServers.origami = {
  command: 'node',
  args: ['$MCP_SERVER_DIR/index.js'],
  env: {}
};

fs.writeFileSync(path, JSON.stringify(config, null, 2) + '\n');
console.log('     Claude Code configured: ' + path);
"
echo ""

# 3. Show instructions
echo "[3/3] Setup complete!"
echo ""
echo "=== Next Steps ==="
echo ""
echo "1. Enable MCP bridge in the Origami Chrome extension:"
echo "   Settings → MCP Bridge → Enable"
echo ""
echo "2. Start Claude Code — the origami MCP server starts automatically."
echo ""
echo "3. In Claude Code, you can now use Origami tools:"
echo "   - scan_page               Trigger a security scan"
echo "   - get_findings_summary    Overview of all findings"
echo "   - get_findings_by_category Detailed findings per category"
echo "   - get_security_score      Security score and grade"
echo "   - get_technologies        Detected tech stack"
echo "   - check_cves              CVE/EOL data"
echo "   - get_attack_chains       Correlated attack chains"
echo "   - assess_risk             Risk scoring via Intent Engine"
echo "   - generate_poc            PoC exploit generation"
echo "   - override_severity       Triage finding severity"
echo "   - send_request            HTTP request through Chrome"
echo "   - get_session_analysis    JWT/session analysis"
echo "   - get_auth_flows          OAuth/SAML flow capture"
echo "   - get_graphql_schema      GraphQL introspection"
echo "   - export_report           Generate security report"
echo "   - get_page_info           Current tab info"
echo ""
echo "=== Configuration ==="
echo "  WebSocket port: 9340 (override with ORIGAMI_WS_PORT env var)"
echo "  Auth token:     auto-generated per session, written to ~/.origami-mcp/ws-token"
echo "                  Set in extension: Settings → MCP Bridge → Token"
echo "                  Or set ORIGAMI_WS_TOKEN env var for a fixed token"
echo "  Verbose mode:   node index.js --verbose"
echo ""
