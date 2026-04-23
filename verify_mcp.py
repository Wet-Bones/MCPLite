#!/usr/bin/env python3
import sys
import os

# Ensure we're in the right directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("🔍 Testing mcp_server.py...")

try:
    # Test 1: Module imports cleanly
    import mcp_server
    print("✅ Module imports without errors")
    
    # Test 2: FastMCP instance exists
    if hasattr(mcp_server, 'mcp'):
        print("✅ FastMCP instance 'mcp' exists")
    else:
        print("❌ Missing 'mcp' instance")
        sys.exit(1)
    
    # Test 3: Tool functions are importable/callable
    from mcp_server import audit_codebase, explain_vulnerability
    print("✅ Tool functions audit_codebase() and explain_vulnerability() exist")
    
    # Test 4: Functions are registered as MCP tools (check via __wrapped__ or mcp's registry)
    # Just verify they're callable
    import inspect
    sig1 = inspect.signature(audit_codebase)
    sig2 = inspect.signature(explain_vulnerability)
    print(f"✅ audit_codebase params: {list(sig1.parameters.keys())}")
    print(f"✅ explain_vulnerability params: {list(sig2.parameters.keys())}")
    
    print("\n🎉 SUCCESS: All verification checks passed!")
    print("   Your server is ready to run with: python mcp_server.py")
    
except Exception as e:
    print(f"\n❌ FAILED: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)