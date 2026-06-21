"""
Debug específico para o payload CASE WHEN
"""
import sys
from pathlib import Path
from urllib.parse import unquote
import re

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from ml_pipeline import get_ml_engine

payload = "' OR CASE WHEN (1=1) THEN 1 ELSE 0 END --"

ml_engine = get_ml_engine()

print(f"Payload original: {payload}\n")

# Testar cada camada da função _is_benign_context
payload_normalized = unquote(payload).lower()
payload_normalized = payload_normalized.replace('+', ' ')

print(f"Payload normalizado: {payload_normalized}\n")

# 1. Genéricos
generic_benign_tokens = {
    'true', 'false', 'null', 'undefined', 'home', 'index', 'default', 
    'admin', 'guest', 'root', 'login', 'signin', 'signup', 'register', 
    'test', 'none', 'na', 'n/a', 'en-us', 'en', 'pt-br', 'pt', 'br', 
    'es', 'fr', 'de', 'www', 'api', 'app', 'dev', 'staging', 'prod',
    'v1', 'v2', 'beta', 'alpha', '404', '200', '500', 'json', 'xml',
    'user', 'id', 'name', 'email', 'password', 'token', 'key', 'value',
    'status', 'error', 'success', 'pending', 'active', 'inactive',
}
if payload_normalized.strip() in generic_benign_tokens:
    print("✓ Matched: Generic benign token")
else:
    print("✗ Not generic benign token")

# 2. Underscores
if '_' in payload_normalized:
    print("✓ Tem underscore")
else:
    print("✗ Sem underscore")

# 3. Frases longas
words = payload_normalized.split()
print(f"\nPalavras: {words}")
print(f"Total de palavras: {len(words)}")

if len(words) >= 5:
    sql_keywords = {'select', 'insert', 'update', 'delete', 'drop', 
                   'where', 'union', 'from', 'join', 'group', 'having',
                   'order', 'by', 'or', 'and', 'not', 'in', 'like',
                   'case', 'when', 'then', 'end', 'else'}
    sql_keyword_count = sum(1 for word in words if word in sql_keywords)
    print(f"SQL keywords encontrados: {sql_keyword_count}")
    for word in words:
        if word in sql_keywords:
            print(f"  - {word}")
    
    if sql_keyword_count <= 2:
        print("✓ <= 2 keywords: considerado benign")
    else:
        print("✗ > 2 keywords: deveria ser detectado como ataque")

# 4. Strong attack signature
print(f"\nTestando _is_strong_attack_signature:")
result = ml_engine._is_strong_attack_signature(payload)
print(f"Resultado: {result}")

# 5. Predição final
print(f"\nPredição final:")
pred = ml_engine.predict_payload(payload)
print(f"  attack_type: {pred.get('attack_type')}")
print(f"  confidence: {pred.get('confidence')}")
print(f"  is_malicious: {pred.get('is_malicious')}")
