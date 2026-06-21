"""
Identificar qual payload SQLI não está sendo detectado
"""
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from ml_pipeline import get_ml_engine

SQLI_VARIATIONS = [
    "1' OR '1'='1",
    "admin'--",
    "' UNION SELECT * FROM passwords --",
    "1/**/OR/**/1=1",
    "1 OR 1=1 --",
    "' OR CASE WHEN (1=1) THEN 1 ELSE 0 END --",
    "admin' + ' OR '1'='1",
    "%27 OR %271%27=%271",
    "1 UNION SELECT NULL, NULL, NULL --",
    "1 UNION SELECT 1,2,3,4,5",
    "1' ORDER BY 1--",
    "1' AND SLEEP(5)--",
    "1' OR SLEEP(5)--",
    "1; DROP TABLE users;--",
    "1' AND '1'='1",
]

ml_engine = get_ml_engine()

print("Testando cada variação de SQLI:\n")
undetected = []
for i, payload in enumerate(SQLI_VARIATIONS, 1):
    result = ml_engine.predict_payload(payload)
    attack_type = result.get('attack_type')
    confidence = result.get('confidence')
    is_malicious = result.get('is_malicious')
    
    if attack_type == 'SQLI':
        status = "✓"
    else:
        status = "❌"
        undetected.append(payload)
    
    attack_display = attack_type or "BENIGN"
    print(f"{status} [{i:2d}] {payload[:40]:40s} → {attack_display:6s} ({confidence:.1%})")

print(f"\nResumo: {len(undetected)} ataques não detectados")
if undetected:
    print("\nPayloads não detectados:")
    for payload in undetected:
        print(f"  - {payload}")

