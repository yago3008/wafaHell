"""
Teste rápido do módulo ml_integration.py
"""
from ml_integration import get_ml_engine

print('=== Testando ML Integration ===\n')
ml = get_ml_engine()

test_cases = [
    ('SELECT * FROM users WHERE id=1', 'SQLI'),
    ("1' OR '1'='1", 'SQLI'),
    ('<script>alert(1)</script>', 'XSS'),
    ('<img src=x onerror=alert(1)>', 'XSS'),
    ('GET /hello?name=john', 'BENIGN'),
    ('user=admin&pass=123456', 'BENIGN'),
]

for payload, expected in test_cases:
    result = ml.predict(payload)
    attack_type = result.get('attack_type') or "BENIGN"
    match = "✓" if attack_type == expected else "✗"
    print(f'{match} Payload: {payload[:40]}')
    print(f'   Expected: {expected}, Got: {attack_type}')
    print(f'   Probs: SQLI={result.get("sqli", 0.0):.3f}, XSS={result.get("xss", 0.0):.3f}, BENIGN={result.get("benign", 0.0):.3f}')
    print(f'   Malicious: {result.get("is_malicious")}')
    print()
