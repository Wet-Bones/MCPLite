#!/usr/bin/env python3
"""
Smoke test for mcp_server.py
Tests imports, dependencies, and tool execution without fragile async clients.
"""

import sys
import subprocess
import time
import json
from pathlib import Path

def test_imports():
    """Test 1: Can we import the module?"""
    print("🔍 Test 1: Module import...")
    try:
        from mcp_server import audit_codebase, explain_vulnerability, mcp
        print("   ✅ Imports successful")
        return True, (audit_codebase, explain_vulnerability)
    except Exception as e:
        print(f"   ❌ Import failed: {e}")
        return False, (None, None)

def test_dependencies():
    """Test 2: Are bandit and gitleaks available?"""
    print("🔍 Test 2: External tools...")
    tools_ok = True
    
    for tool in ["bandit", "gitleaks"]:
        try:
            result = subprocess.run([tool, "--version"], 
                                capture_output=True, 
                                timeout=5,
                                encoding='utf-8')
            if result.returncode == 0:
                print(f"   ✅ {tool} available")
            else:
                print(f"   ⚠️  {tool} returned error")
                tools_ok = False
        except FileNotFoundError:
            print(f"   ❌ {tool} not found in PATH")
            print(f"      Fix: pip install {tool} (for bandit) or scoop install {tool}")
            tools_ok = False
        except Exception as e:
            print(f"   ❌ {tool} error: {e}")
            tools_ok = False
    
    return tools_ok

def test_tool_execution(audit_func, explain_func):
    """Test 3: Do the tools actually run?"""
    print("🔍 Test 3: Tool execution...")
    
    # Test audit_codebase on current directory
    try:
        print("   → Running audit_codebase('.')...")
        result = audit_func(".")
        
        vuln_count = result.get('summary', {}).get('vuln_count', 0)
        secret_count = result.get('summary', {}).get('secret_count', 0)
        
        print(f"   ✅ audit_codebase returned")
        print(f"      Found: {vuln_count} vulns, {secret_count} secrets")
        
        # Validate structure
        if 'vulnerabilities' in result and 'secrets' in result:
            print("   ✅ Result structure valid")
        else:
            print("   ⚠️  Missing expected keys in result")
            
    except Exception as e:
        print(f"   ❌ audit_codebase failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test explain_vulnerability
    try:
        print("   → Running explain_vulnerability('CVE-2021-44228')...")
        result = explain_func("CVE-2021-44228")
        
        if result.get('cve_id') == "CVE-2021-44228":
            print(f"   ✅ explain_vulnerability returned valid response")
        else:
            print(f"   ⚠️  Unexpected response format")
            
    except Exception as e:
        print(f"   ❌ explain_vulnerability failed: {e}")
        return False
    
    return True

def test_server_starts():
    """Test 4: Does the server process start and stay alive?"""
    print("🔍 Test 4: Server startup...")
    
    try:
        proc = subprocess.Popen(
            [sys.executable, "-u", "mcp_server.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8'
        )
        
        # Give it time to initialize
        time.sleep(2)
        
        # Check if still running
        if proc.poll() is None:
            print("   ✅ Server process started and running (PID: {})".format(proc.pid))
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except:
                proc.kill()
            return True
        else:
            stderr = proc.stderr.read()
            print(f"   ❌ Server crashed immediately")
            print(f"   Error: {stderr[:500]}")
            return False
            
    except Exception as e:
        print(f"   ❌ Failed to start server: {e}")
        return False

def main():
    """Run all smoke tests"""
    print("=" * 50)
    print("MCP Server Smoke Test")
    print("=" * 50)
    print()
    
    results = []
    
    # Run tests
    import_ok, (audit_func, explain_func) = test_imports()
    results.append(("Imports", import_ok))
    
    if not import_ok:
        print("\n❌ Critical failure: Cannot import module. Fix syntax errors first.")
        sys.exit(1)
    
    deps_ok = test_dependencies()
    results.append(("Dependencies", deps_ok))
    
    if audit_func and explain_func:
        exec_ok = test_tool_execution(audit_func, explain_func)
        results.append(("Tool Execution", exec_ok))
    else:
        results.append(("Tool Execution", False))
    
    server_ok = test_server_starts()
    results.append(("Server Startup", server_ok))
    
    # Summary
    print()
    print("=" * 50)
    print("SMOKE TEST RESULTS")
    print("=" * 50)
    
    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {name}")
        if not passed:
            all_passed = False
    
    print()
    if all_passed:
        print("🎉 ALL TESTS PASSED - Phase 1 Complete!")
        print("   Ready for Claude Desktop integration.")
        return 0
    else:
        print("⚠️  SOME TESTS FAILED - See errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())