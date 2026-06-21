"""
Script de análise completa de performance do modelo wafaHell

Testa:
1. Acurácia, Recall, Precisão, F1-Score
2. Taxa de Falsos Positivos (FPR)
3. Latência de predição
4. Comparação com objetivos do TCC
"""

import time
import numpy as np
from sklearn.metrics import (
    accuracy_score, recall_score, precision_score, f1_score,
    confusion_matrix, classification_report
)
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

# ============================================================================
# CONJUNTOS DE TESTE MANUALMENTE CRIADOS
# ============================================================================

# SQLI - Ataques conhecidos
SQLI_PAYLOADS = [
    "SELECT * FROM users WHERE id=1",
    "1' OR '1'='1",
    "admin' --",
    "' UNION SELECT * FROM passwords --",
    "1; DROP TABLE users;--",
    "' OR 1=1--",
    "SELECT * FROM users WHERE username='admin' AND password='",
    "1' AND '1'='1",
    "SELECT user, password FROM admin WHERE username=",
    "%' OR '1'='1",
    "1' OR 'a'='a",
    "SELECT COUNT(*) FROM users WHERE login='' OR '1'='1",
    "' OR ''='",
    "admin'#",
    "1' UNION ALL SELECT NULL,NULL,NULL--",
]

# XSS - Ataques conhecidos
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert('xss')>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert('xss')>",
    "<input onfocus=alert('xss') autofocus>",
    "javascript:alert('xss')",
    "<img src=x onerror='alert(1)'>",
    "<div onclick=alert('xss')>click</div>",
    "<marquee onstart=alert('xss')></marquee>",
    "<details open ontoggle=alert('xss')>",
    "<embed src='javascript:alert(1)'>",
    "<object data='javascript:alert(1)'>",
    "<link rel='stylesheet' href='javascript:alert(1)'>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
]

# BENIGNO - Requisições legítimas
BENIGN_PAYLOADS = [
    "user=john&password=123456",
    "search=python",
    "id=42&category=books",
    "name=Alice&email=alice@example.com",
    "page=1&limit=20",
    "token=abc123xyz789",
    "api_key=sk_live_1234567890",
    "action=list&format=json",
    "query=hello world",
    "filter=active",
    "sort_by=date",
    "lang=en-US",
    "version=2.0",
    "debug=false",
    "timeout=30",
]

# Payloads benignos que poderiam gerar falsos positivos (edge cases)
EDGE_CASE_PAYLOADS = [
    "SELECT your favorite color",  # Contém SELECT mas é legítimo
    "I need to select the items where value is true",  # Contém SELECT, WHERE, true
    "where_are_you",  # Contém WHERE
    "union-members-list",  # Contém UNION
    "drop_this_feature",  # Contém DROP
    "insert_coin_here",  # Contém INSERT
    "update_profile",  # Contém UPDATE
    "delete_account",  # Contém DELETE (mas em contexto legítimo)
    "<important>news</important>",  # Contém tags HTML mas legítimo
    "home=true&active=true",  # Contém true
    "undefined",  # Valor comum em JS
    "null_value",  # Contém null
    "request_id=123",  # Normal
    "timestamp=2024-01-01",  # Normal
    "user_agent=Mozilla/5.0",  # Normal
]

# ============================================================================
# CARREGAR MODELO
# ============================================================================

def load_model():
    """Carrega o modelo de ML."""
    try:
        from ml_pipeline import get_ml_engine
        print("✅ Carregando modelo...")
        ml_engine = get_ml_engine()
        return ml_engine
    except Exception as e:
        print(f"❌ Erro ao carregar modelo: {e}")
        return None

# ============================================================================
# TESTE DE PREDIÇÃO
# ============================================================================

def run_prediction_test(ml_engine):
    """Executa predições e calcula métricas."""
    
    print("\n" + "="*80)
    print("TESTE 1: PREDIÇÕES E ACURÁCIA")
    print("="*80)
    
    # Preparar dataset
    payloads = SQLI_PAYLOADS + XSS_PAYLOADS + BENIGN_PAYLOADS
    y_true = [0]*len(SQLI_PAYLOADS) + [1]*len(XSS_PAYLOADS) + [2]*len(BENIGN_PAYLOADS)
    
    y_pred = []
    predictions_detail = []
    latencies = []
    
    print(f"\nTestando {len(payloads)} payloads...")
    print(f"  - {len(SQLI_PAYLOADS)} SQLI")
    print(f"  - {len(XSS_PAYLOADS)} XSS")
    print(f"  - {len(BENIGN_PAYLOADS)} BENIGN")
    
    for i, payload in enumerate(payloads):
        start = time.time()
        result = ml_engine.predict_payload(payload)
        elapsed = (time.time() - start) * 1000  # ms
        latencies.append(elapsed)
        
        # Mapear resultado para classe
        attack_type = result.get('attack_type')
        if attack_type == 'SQLI':
            pred_class = 0
        elif attack_type == 'XSS':
            pred_class = 1
        else:
            pred_class = 2  # BENIGN
        
        y_pred.append(pred_class)
        predictions_detail.append({
            'payload': payload[:50],
            'true': ['SQLI', 'XSS', 'BENIGN'][y_true[i]],
            'pred': ['SQLI', 'XSS', 'BENIGN'][pred_class],
            'confidence': result.get('confidence', 0),
            'latency_ms': elapsed
        })
    
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    
    # Calcular métricas
    accuracy = accuracy_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
    precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    
    print(f"\n📊 MÉTRICAS GERAIS:")
    print(f"  Acurácia:   {accuracy*100:.2f}%")
    print(f"  Recall:     {recall*100:.2f}%")
    print(f"  Precisão:   {precision*100:.2f}%")
    print(f"  F1-Score:   {f1*100:.2f}%")
    
    # Métricas por classe
    print(f"\n📊 MÉTRICAS POR CLASSE:")
    for class_idx, class_name in enumerate(['SQLI', 'XSS', 'BENIGN']):
        mask = y_true == class_idx
        if mask.sum() > 0:
            class_recall = recall_score(y_true[mask], y_pred[mask], average='binary', zero_division=0, pos_label=class_idx)
            class_precision = precision_score(y_true[mask], y_pred[mask], average='binary', zero_division=0, pos_label=class_idx)
            class_f1 = f1_score(y_true[mask], y_pred[mask], average='binary', zero_division=0, pos_label=class_idx)
            print(f"  {class_name}: Recall={class_recall*100:.1f}%, Precision={class_precision*100:.1f}%, F1={class_f1*100:.1f}%")
    
    # Latência
    avg_latency = np.mean(latencies)
    p50_latency = np.percentile(latencies, 50)
    p95_latency = np.percentile(latencies, 95)
    p99_latency = np.percentile(latencies, 99)
    
    print(f"\n⏱️ LATÊNCIA:")
    print(f"  Média:      {avg_latency:.2f} ms")
    print(f"  P50:        {p50_latency:.2f} ms")
    print(f"  P95:        {p95_latency:.2f} ms")
    print(f"  P99:        {p99_latency:.2f} ms")
    
    # Matriz de confusão
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2])
    print(f"\n📋 MATRIZ DE CONFUSÃO:")
    print(f"           SQLI  XSS  BENIGN")
    print(f"  SQLI    {cm[0,0]:4d} {cm[0,1]:4d} {cm[0,2]:4d}")
    print(f"  XSS     {cm[1,0]:4d} {cm[1,1]:4d} {cm[1,2]:4d}")
    print(f"  BENIGN  {cm[2,0]:4d} {cm[2,1]:4d} {cm[2,2]:4d}")
    
    return {
        'accuracy': accuracy,
        'recall': recall,
        'precision': precision,
        'f1': f1,
        'latency_mean': avg_latency,
        'latency_p95': p95_latency,
        'y_true': y_true,
        'y_pred': y_pred,
        'predictions_detail': predictions_detail
    }

# ============================================================================
# TESTE DE FALSOS POSITIVOS
# ============================================================================

def test_false_positives(ml_engine):
    """Testa taxa de falsos positivos em edge cases."""
    
    print("\n" + "="*80)
    print("TESTE 2: FALSOS POSITIVOS - EDGE CASES")
    print("="*80)
    
    print(f"\nTestando {len(EDGE_CASE_PAYLOADS)} casos edge benignos...")
    
    false_positives = 0
    fp_details = []
    
    for payload in EDGE_CASE_PAYLOADS:
        result = ml_engine.predict_payload(payload)
        is_malicious = result.get('is_malicious', False)
        
        if is_malicious:
            false_positives += 1
            fp_details.append({
                'payload': payload,
                'confidence': result.get('confidence', 0),
                'attack_type': result.get('attack_type')
            })
    
    fpr = (false_positives / len(EDGE_CASE_PAYLOADS)) * 100
    
    print(f"\n🚨 FALSOS POSITIVOS:")
    print(f"  Total testado: {len(EDGE_CASE_PAYLOADS)}")
    print(f"  Falsos positivos: {false_positives}")
    print(f"  Taxa (FPR): {fpr:.2f}%")
    
    if fp_details:
        print(f"\n  Payloads incorretamente bloqueados:")
        for fp in fp_details:
            print(f"    - '{fp['payload']}' → {fp['attack_type']} ({fp['confidence']:.1%})")
    
    return fpr, fp_details

# ============================================================================
# TESTE DE DETECÇÃO REAL
# ============================================================================

def test_detection_rates(ml_engine):
    """Testa taxas de detecção de ataques reais."""
    
    print("\n" + "="*80)
    print("TESTE 3: TAXA DE DETECÇÃO DE ATAQUES REAIS")
    print("="*80)
    
    # Testar SQLI
    print(f"\n📌 SQL Injection ({len(SQLI_PAYLOADS)} payloads):")
    sqli_detected = 0
    for payload in SQLI_PAYLOADS:
        result = ml_engine.predict_payload(payload)
        if result.get('attack_type') == 'SQLI':
            sqli_detected += 1
    sqli_rate = (sqli_detected / len(SQLI_PAYLOADS)) * 100
    print(f"  Detectados: {sqli_detected}/{len(SQLI_PAYLOADS)} ({sqli_rate:.1f}%)")
    
    # Testar XSS
    print(f"\n📌 Cross-Site Scripting ({len(XSS_PAYLOADS)} payloads):")
    xss_detected = 0
    for payload in XSS_PAYLOADS:
        result = ml_engine.predict_payload(payload)
        if result.get('attack_type') == 'XSS':
            xss_detected += 1
    xss_rate = (xss_detected / len(XSS_PAYLOADS)) * 100
    print(f"  Detectados: {xss_detected}/{len(XSS_PAYLOADS)} ({xss_rate:.1f}%)")
    
    return sqli_rate, xss_rate

# ============================================================================
# COMPARAÇÃO COM OBJETIVOS DO TCC
# ============================================================================

def compare_with_tcc_goals(results, fpr):
    """Compara resultados com objetivos do TCC."""
    
    print("\n" + "="*80)
    print("COMPARAÇÃO COM OBJETIVOS DO TCC")
    print("="*80)
    
    # Objetivos
    print("\n🎯 OBJETIVOS DO TCC:")
    print("  1. FPR < 0.5%")
    print("  2. Recall > 95%")
    print("  3. F1-Score > 95%")
    print("  4. Latência P95 < 100ms")
    
    # Resultados
    print("\n✅ RESULTADOS ATUAIS:")
    print(f"  1. FPR = {fpr:.2f}% {'✓' if fpr < 0.5 else '✗'}")
    print(f"  2. Recall = {results['recall']*100:.2f}% {'✓' if results['recall'] > 0.95 else '✗'}")
    print(f"  3. F1-Score = {results['f1']*100:.2f}% {'✓' if results['f1'] > 0.95 else '✗'}")
    print(f"  4. Latência P95 = {results['latency_p95']:.2f}ms {'✓' if results['latency_p95'] < 100 else '✗'}")
    
    # Summary
    goals_met = 0
    if fpr < 0.5: goals_met += 1
    if results['recall'] > 0.95: goals_met += 1
    if results['f1'] > 0.95: goals_met += 1
    if results['latency_p95'] < 100: goals_met += 1
    
    print(f"\n📊 OBJETIVOS ALCANÇADOS: {goals_met}/4")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("\n" + "="*80)
    print("ANÁLISE COMPLETA DE PERFORMANCE - WAFAHELL")
    print("="*80)
    
    # Carregar modelo
    ml_engine = load_model()
    if not ml_engine:
        sys.exit(1)
    
    # Teste 1: Acurácia e métricas
    results = run_prediction_test(ml_engine)
    
    # Teste 2: Falsos positivos
    fpr, fp_details = test_false_positives(ml_engine)
    
    # Teste 3: Taxa de detecção
    sqli_rate, xss_rate = test_detection_rates(ml_engine)
    
    # Comparação com objetivos
    compare_with_tcc_goals(results, fpr)
    
    print("\n" + "="*80)
    print("FIM DA ANÁLISE")
    print("="*80)
