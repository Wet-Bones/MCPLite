# MCPLiteServer - MCP Security Audit Server

A production-ready Model Context Protocol (MCP) server with **async concurrent scanning**, **pluggable security tools**, and **secret redaction** for safe CI/CD integration.

## Features

- ⚡ **Async Concurrent Scanning**: Bandit + Gitleaks run in parallel via `asyncio.gather()`
- 🔌 **Plugin Architecture**: Easy to add scanners (Semgrep, Trivy, CodeQL) via `BaseScanner` ABC
- 🔒 **Secret Redaction**: Gitleaks shows secret length, never the actual credential
- 🔍 **Bandit Integration**: Python static analysis (SQL injection, hardcoded passwords, unsafe subprocess)
- 🔐 **Gitleaks Integration**: Credential detection with fingerprinting
- ✅ **CVE Validation**: Regex-enforced CVE format checking (API connection needed)
- 🖥️ **Windows Optimized**: `CREATE_NO_WINDOW` + `DEVNULL` prevents console deadlocks
- 🔧 **Claude Desktop Native**: Seamless MCP integration (also works with VS Code!)


## Plugin System

Add new scanners by subclassing `BaseScanner`:

```python
class SemgrepScanner(BaseScanner):
    async def scan(self, path: Path) -> Any:
        # Your async implementation
        ...
    def normalize(self, raw: Any) -> List[Dict]:
        # Normalize to shared schema
        ...
```

then make sure the new scanner is registered

```python
_auditor.register_scanner("semgrep", SemgrepScanner())
```


## Prerequisites:

Python 3.11+ (async/await required)
Windows 10/11 (Linux/macOS supported, console flags differ)
Bandit: pip install bandit
Gitleaks: scoop install gitleaks


## Claude Sample Config:

{
  "mcpServers": {
    "SecurityAuditServer": {
      "command": "C:\\path\\to\\mcp-liteserver\\venv\\Scripts\\python.exe",
      "args": ["-u", "C:\\path\\to\\mcp-liteserver\\mcp_server.py"]
    }
  }
}
