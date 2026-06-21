"""
advanced_test_suite.py

Suite de testes avançada para wafaHell:
1. Stress testing (100+ payloads)
2. Payload variations (obfuscações)
3. Performance comparison
4. Report generation
"""

import time
import json
import numpy as np
from datetime import datetime
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

# ============================================================================
# CONJUNTOS DE TESTE EXPANDIDOS
# ============================================================================

# Variações de SQLI
SQLI_VARIATIONS = [
    # Clássicos
    "1' OR '1'='1",
    "admin'--",
    "' UNION SELECT * FROM passwords --",
    
    # Com comentários
    "1/**/OR/**/1=1",
    "1 OR 1=1 --",
    
    # Com CASE
    "' OR CASE WHEN (1=1) THEN 1 ELSE 0 END --",
    
    # Com concatenação
    "admin' + ' OR '1'='1",
    
    # Com encoding
    "%27 OR %271%27=%271",
    
    # Variações do UNION
    "1 UNION SELECT NULL, NULL, NULL --",
    "1 UNION SELECT 1,2,3,4,5",
    
    # ORDER BY
    "1' ORDER BY 1--",
    
    # TIME-BASED
    "1' AND SLEEP(5)--",
    "1' OR SLEEP(5)--",
    
    # STACKED QUERIES
    "1; DROP TABLE users;--",
    
    # Boolean-based
    "1' AND '1'='1",
]

# Variações de XSS
XSS_VARIATIONS = [
    # Alert boxes
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    
    # Event handlers
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe onload=alert(1)>",
    
    # Data URI
    "<img src='data:text/html,<script>alert(1)</script>'>",
    
    # With encoding
    "<img src=x onerror='eval(atob(\"YWxlcnQoMSk=\"))'>",
    
    # SVG attacks
    "<svg><script>alert(1)</script></svg>",
    
    # Style attribute
    "<div style=\"background:url(javascript:alert(1))\"></div>",
    
    # Input onfocus
    "<input autofocus onfocus=alert(1)>",
    
    # HTML5 video
    "<video src=x onerror=alert(1)>",
    
    # Details/summary
    "<details open ontoggle=alert(1)>",
    
    # Form
    "<form action=javascript:alert(1)>",
    
    # Marquee
    "<marquee onstart=alert(1)>",
]

# Payloads benignos variados
BENIGN_VARIATIONS = [
    # URLs/domains
    "example.com",
    "https://example.com/path",
    "api.github.com",
    
    # Formatos comuns
    "2024-01-01",
    "2024-01-01T12:30:00Z",
    
    # Valores comuns
    "john@example.com",
    "user123",
    "12345",
    "0.0.0.0",
    "192.168.1.1",
    
    # Parametros típicos
    "page=1&limit=10&sort=date",
    "search=hello&filter=active",
    
    # Valores JSON
    '{"status":"ok","count":10}',
    '["item1","item2","item3"]',
    
    # UUIDs
    "550e8400-e29b-41d4-a716-446655440000",
    
    # Caminhos
    "/api/users",
    "/dashboard",
    "/admin/settings",
]

# ============================================================================
# TESTES AVANÇADOS
# ============================================================================

def load_model():
    """Carrega o modelo."""
    try:
        from ml_pipeline import get_ml_engine
        return get_ml_engine()
    except Exception as e:
        print(f"❌ Erro: {e}")
        return None

def stress_test(ml_engine):
    """Teste de carga com muitos payloads."""
    print("\n" + "="*80)
    print("TESTE 1: STRESS TEST (100+ PAYLOADS)")
    print("="*80)
    
    all_payloads = SQLI_VARIATIONS + XSS_VARIATIONS + BENIGN_VARIATIONS
    print(f"\nTestando {len(all_payloads)} payloads...")
    
    start_time = time.time()
    latencies = []
    results_by_class = {'SQLI': 0, 'XSS': 0, 'BENIGN': 0}
    errors = 0
    
    for i, payload in enumerate(all_payloads):
        try:
            start = time.time()
            result = ml_engine.predict_payload(payload)
            elapsed = (time.time() - start) * 1000
            latencies.append(elapsed)
            
            attack_type = result.get('attack_type') or 'BENIGN'
            results_by_class[attack_type] += 1
            
            if (i + 1) % 20 == 0:
                print(f"  [{i+1:3d}/{len(all_payloads)}] Processado...")
        except Exception as e:
            errors += 1
            print(f"  ❌ Erro no payload {i+1}: {e}")
    
    total_time = time.time() - start_time
    
    print(f"\n📊 RESULTADOS DO STRESS TEST:")
    print(f"  Total processado: {len(all_payloads)} payloads")
    print(f"  Tempo total: {total_time:.2f}s")
    print(f"  Throughput: {len(all_payloads)/total_time:.1f} payloads/sec")
    print(f"  Erros: {errors}")
    
    print(f"\n📊 CLASSIFICAÇÕES:")
    for cls, count in sorted(results_by_class.items()):
        pct = (count / len(all_payloads)) * 100
        print(f"  {cls}: {count:3d} ({pct:5.1f}%)")
    
    print(f"\n⏱️  LATÊNCIA:")
    print(f"  Média: {np.mean(latencies):.2f}ms")
    print(f"  Min: {np.min(latencies):.2f}ms")
    print(f"  Max: {np.max(latencies):.2f}ms")
    print(f"  Mediana: {np.median(latencies):.2f}ms")
    print(f"  P95: {np.percentile(latencies, 95):.2f}ms")
    print(f"  P99: {np.percentile(latencies, 99):.2f}ms")
    
    return {
        'total': len(all_payloads),
        'latencies': latencies,
        'results': results_by_class,
        'errors': errors
    }

def payload_variation_test(ml_engine):
    """Testa se variações de payloads são detectadas."""
    print("\n" + "="*80)
    print("TESTE 2: DETECÇÃO DE VARIAÇÕES")
    print("="*80)
    
    test_sets = {
        'SQLI Variations': SQLI_VARIATIONS,
        'XSS Variations': XSS_VARIATIONS,
    }
    
    results = {}
    for category, payloads in test_sets.items():
        detected = 0
        for payload in payloads:
            result = ml_engine.predict_payload(payload)
            is_attack = result.get('is_malicious', False)
            if is_attack:
                detected += 1
        
        rate = (detected / len(payloads)) * 100
        results[category] = {'detected': detected, 'total': len(payloads), 'rate': rate}
        
        status = "✓" if rate >= 95 else "⚠" if rate >= 80 else "❌"
        print(f"\n📌 {category}:")
        print(f"  {status} Detectados: {detected}/{len(payloads)} ({rate:.1f}%)")
        
        if rate < 100:
            print(f"  ⚠️  Alguns ataques não foram detectados!")
    
    return results

def performance_comparison(ml_engine):
    """Compara performance entre categorias."""
    print("\n" + "="*80)
    print("TESTE 3: COMPARAÇÃO DE PERFORMANCE")
    print("="*80)
    
    categories = {
        'SQLI': SQLI_VARIATIONS[:5],
        'XSS': XSS_VARIATIONS[:5],
        'BENIGN': BENIGN_VARIATIONS[:5],
    }
    
    for category, payloads in categories.items():
        latencies = []
        for payload in payloads:
            start = time.time()
            ml_engine.predict_payload(payload)
            elapsed = (time.time() - start) * 1000
            latencies.append(elapsed)
        
        print(f"\n📌 {category}:")
        print(f"  Média: {np.mean(latencies):.2f}ms")
        print(f"  Min/Max: {np.min(latencies):.2f}ms / {np.max(latencies):.2f}ms")

def generate_json_report(stress_results, variation_results):
    """Gera relatório em JSON."""
    print("\n" + "="*80)
    print("TESTE 4: GERAÇÃO DE RELATÓRIO")
    print("="*80)
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'stress_test': {
            'total_payloads': stress_results['total'],
            'average_latency_ms': float(np.mean(stress_results['latencies'])),
            'p95_latency_ms': float(np.percentile(stress_results['latencies'], 95)),
            'p99_latency_ms': float(np.percentile(stress_results['latencies'], 99)),
            'classifications': stress_results['results'],
            'errors': stress_results['errors']
        },
        'variation_detection': variation_results
    }
    
    report_path = BASE_DIR / 'advanced_test_report.json'
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✅ Relatório salvo: {report_path}")
    return report

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("\n" + "="*80)
    print("SUITE DE TESTES AVANÇADA - WAFAHELL")
    print("="*80)
    
    ml_engine = load_model()
    if not ml_engine:
        sys.exit(1)
    
    # Teste 1: Stress test
    stress_results = stress_test(ml_engine)
    
    # Teste 2: Variações
    variation_results = payload_variation_test(ml_engine)
    
    # Teste 3: Comparação
    performance_comparison(ml_engine)
    
    # Teste 4: Relatório JSON
    report = generate_json_report(stress_results, variation_results)
    
    print("\n" + "="*80)
    print("FIM DA SUITE DE TESTES AVANÇADA")
    print("="*80)
