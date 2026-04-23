import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any, Union
import sys

def run_bandit(path: str) -> List[Dict[str, Any]]:
    """
    Run bandit on target path and return normalized findings.
    
    Windows/Git Bash specific: Handles CRLF encoding and path conversion.
    """
    # Resolve path (handles Git Bash /c/Users/... -> C:\Users\...)
    target_path = Path(path).resolve()
    
    if not target_path.exists():
        return [{"error": f"Path not found: {target_path}"}]
    
    try:
        # Use subprocess.run instead of check_output to handle Bandit's exit code 1
        # Bandit exits 1 when it finds issues (normal behavior), 0 when clean
        result = subprocess.run(
            [
                sys.executable, "-m", "bandit",  # Use python -m bandit for Windows safety
                "-r", 
                str(target_path), 
                "-f", "json",      # Machine-readable output
                "-q",              # Quiet: suppress progress output
                "--exit-zero"      # Optional: force exit 0 even if issues found (simpler handling)
            ],
            capture_output=True,
            text=True,
            encoding='utf-8',      # Windows Git Bash sometimes defaults to cp1252
            errors='replace'       # Don't crash on encoding errors
        )
        
        # Parse JSON output
        if result.stdout:
            try:
                bandit_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                return [{"error": "Failed to parse bandit JSON", "raw_output": result.stdout[:500]}]
        else:
            bandit_data = {"results": []}
        
        # Normalize to your schema
        return _normalize_bandit_results(bandit_data)
        
    except FileNotFoundError:
        return [{"error": "bandit not found. Ensure: pip install bandit"}]
    except Exception as e:
        return [{"error": f"Unexpected error: {str(e)}"}]

def _normalize_bandit_results(data: Dict) -> List[Dict[str, Any]]:
    """
    Convert Bandit JSON to your normalized schema:
    {
        "type": "security-warning",
        "tool": "bandit", 
        "description": "...",
        "file": "...",
        "line": 1
    }
    """
    normalized = []
    
    for issue in data.get("results", []):
        normalized.append({
            "type": "security-warning",
            "tool": "bandit",
            "test_id": issue.get("test_id"),
            "description": issue.get("issue_text", ""),
            "file": issue.get("filename", ""),
            "line": issue.get("line_number", 0),
            "severity": issue.get("issue_severity", "UNKNOWN").lower(),
            "confidence": issue.get("issue_confidence", "UNKNOWN").lower(),
            "cwe": issue.get("issue_cwe", {}).get("id", "N/A"),
            "more_info": issue.get("more_info", "")
        })
    
    return normalized