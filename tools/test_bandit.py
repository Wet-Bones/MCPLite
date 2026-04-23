from bandit_integration import run_bandit
import tempfile
import os

def test_bandit_finds_hardcoded_password():
    with tempfile.TemporaryDirectory() as tmp_dir:
        file_path = os.path.join(tmp_dir, 'test_file.py')
        with open(file_path, 'w') as f:
            f.write('PASSWORD = "secret123"\n')
        
        # Test on the temp file (use directory for bandit -r)
        results = run_bandit(tmp_dir)
        
        # Should find the hardcoded password
        assert any(r.get("test_id") == "B105" for r in results if "error" not in r)

def test_bandit_handles_clean_file():
    with tempfile.TemporaryDirectory() as tmp_dir:
        file_path = os.path.join(tmp_dir, 'test_file.py')
        with open(file_path, 'w') as f:
            f.write('x = 1 + 1\n')
        
        results = run_bandit(tmp_dir)
        # Should return empty list or low-severity only
        assert all(r.get("severity") != "HIGH" for r in results if "error" not in r)