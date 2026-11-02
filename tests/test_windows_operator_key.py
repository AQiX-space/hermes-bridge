from pathlib import Path

def test_script_is_fail_closed():
 s=(Path(__file__).resolve().parents[1]/'tools/windows_operator_key.ps1').read_text()
 assert 'if(-not $Apply)' in s
 assert 'MISSING_OPERATOR_KEY' in s
 assert 'ReparsePoint' in s
 assert 'Administrator elevation required' in s
 assert '.backup-' in s
 assert 'icacls.exe' in s
 assert '*S-1-5-32-544:F' in s
 assert '*S-1-5-18:F' in s
 assert 'ALREADY_AUTHORIZED' in s
