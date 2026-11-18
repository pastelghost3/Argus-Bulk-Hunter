import sys
sys.path.append('argus-core/scripts')
from scanners.verifier import SecretVerifier

v = SecretVerifier()

# Test 1: A known fake AWS key format
print("Testing AWS Key...")
print(v.identify_and_verify("AKIAIOSFODNN7EXAMPLE"))

# Test 2: A database URL with an internal IP
print("\nTesting DB URL...")
print(v.identify_and_verify("postgresql://crm:LiveUrlPw2@10.0.0.8:5432/crm"))

# Test 3: A GitHub PAT (Replace with a dummy if you don't want to use a real one)
print("\nTesting GitHub PAT...")
print(v.identify_and_verify("ghp_1234567890abcdefghijklmnopqrstuvwxyz"))
