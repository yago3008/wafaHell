"""
test_integration.py — Testes de validação da integração dataset_pipeline ↔ wafaHell

Executa:
1. Validação de estrutura de arquivos
2. Carregamento de modelos
3. Testes de predição
4. Testes de middleware
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent


def test_file_structure():
    """Verifica se todos os arquivos esperados existem."""
    print("\n" + "="*70)
    print("  TEST 1: Estrutura de Arquivos")
    print("="*70)
    
    required_files = [
        "ml_pipeline.py",
        "ml_integration.py",
        "middleware.py",
        "dataset_integration.py",
        "app.py",
    ]
    
    missing = []
    for filename in required_files:
        path = BASE_DIR / filename
        if path.exists():
            print(f"✅ {filename}")
        else:
            print(f"❌ {filename} - FALTANDO")
            missing.append(filename)
    
    return len(missing) == 0


def test_model_loading():
    """Testa se o modelo de ML carrega corretamente."""
    print("\n" + "="*70)
    print("  TEST 2: Carregamento do Modelo ML")
    print("="*70)
    
    try:
        from ml_pipeline import get_ml_engine
        print("✅ Importou get_ml_engine")
        
        engine = get_ml_engine()
        print(f"✅ Modelo carregado: {type(engine).__name__}")
        
        # Verifica atributos críticos
        if hasattr(engine, 'model'):
            print("✅ Atributo 'model' presente")
        else:
            print("❌ Atributo 'model' ausente")
            return False
        
        if hasattr(engine, 'predict_payload'):
            print("✅ Método 'predict_payload' presente")
        else:
            print("❌ Método 'predict_payload' ausente")
            return False
        
        return True
    except Exception as e:
        print(f"❌ Erro ao carregar modelo: {e}")
        return False


def test_payload_prediction():
    """Testa se o modelo consegue fazer predições."""
    print("\n" + "="*70)
    print("  TEST 3: Predição de Payloads")
    print("="*70)
    
    try:
        from ml_pipeline import get_ml_engine
        
        engine = get_ml_engine()
        
        test_cases = [
            {
                "payload": "' OR '1'='1",
                "expected": "SQLI",
                "description": "SQL Injection clássica"
            },
            {
                "payload": "<script>alert('xss')</script>",
                "expected": "XSS",
                "description": "XSS via script tag"
            },
            {
                "payload": "usuario=joao&senha=123",
                "expected": None,
                "description": "Payload benigno"
            },
            {
                "payload": "SELECT * FROM users WHERE id=1",
                "expected": "SQLI",
                "description": "SELECT direto"
            },
        ]
        
        all_pass = True
        for test in test_cases:
            result = engine.predict_payload(test["payload"])
            attack_type = result.get('attack_type')
            confidence = result.get('confidence', 0)
            
            # Validar estrutura do retorno
            required_keys = {'sqli', 'xss', 'benign', 'attack_type', 'confidence', 'is_malicious'}
            if not required_keys.issubset(result.keys()):
                print(f"❌ {test['description']}: estrutura incompleta")
                print(f"   Retornou: {list(result.keys())}")
                all_pass = False
                continue
            
            # Validar predição
            if attack_type == test['expected']:
                status = "✅"
            else:
                status = "⚠"
                all_pass = False
            
            print(f"{status} {test['description']}")
            print(f"   Payload: {test['payload'][:40]}...")
            print(f"   Predito: {attack_type} (confiança: {confidence:.2%})")
            print(f"   Esperado: {test['expected']}")
        
        return all_pass
    except Exception as e:
        print(f"❌ Erro ao fazer predição: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_edge_case_whitelist():
    """Testa se edge cases benignos são mantidos como benignos."""
    print("\n" + "="*70)
    print("  TEST 4: Edge Cases Benignos")
    print("="*70)

    try:
        from ml_pipeline import get_ml_engine
        from middleware import Wafahell

        engine = get_ml_engine()
        waf = object.__new__(Wafahell)

        edge_cases = [
            'SELECT your favorite color',
            "It's a beautiful day",
            'WHERE can I find the menu?',
            'DROP the ball and run',
            'UNION of states formed in 1776',
            'INSERT your name here',
            'NULL value in philosophy',
            'sleep(8) hours for recovery',
            '1=1 is always true in math',
            '100% OR money back guaranteed',
            'table_name for the reservation',
            'exec summary of the report',
            'my password is hunter2',
            'user@domain.com OR notify me',
            'price > 100 AND category = shoes',
        ]

        all_pass = True
        for payload in edge_cases:
            result = engine.predict_payload(payload)
            if result.get('is_malicious'):
                print(f"❌ False positive no ML: {payload}")
                all_pass = False
            elif not waf._is_known_benign_payload(payload):
                print(f"❌ Edge case não reconhecido no middleware: {payload}")
                all_pass = False
            else:
                print(f"✅ {payload}")

        return all_pass
    except Exception as e:
        print(f"❌ Erro ao testar edge cases: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_middleware_initialization():
    """Testa se o middleware inicializa sem erros."""
    print("\n" + "="*70)
    print("  TEST 4: Inicialização do Middleware")
    print("="*70)
    
    try:
        from flask import Flask
        from middleware import Wafahell
        
        app = Flask(__name__)
        print("✅ Flask app criado")
        
        waf = Wafahell(
            app=app,
            dashboard_path='/test/dashboard',
            block_duration=5,
            ai_threshold=0.70,
            monitor_mode=True  # Importante: modo monitor para testes
        )
        print("✅ Wafahell inicializado")
        
        # Verificar atributos corrigidos
        if hasattr(waf, 'block_duration'):
            print("✅ Atributo 'block_duration' presente (corrigido de 'block_durantion')")
        else:
            print("❌ Atributo 'block_duration' ausente")
            return False
        
        if hasattr(waf, 'ai_threshold'):
            print("✅ Atributo 'ai_threshold' presente (corrigido de 'ai_treshold')")
        else:
            print("❌ Atributo 'ai_threshold' ausente")
            return False
        
        if hasattr(waf, 'ai_engine'):
            print("✅ Motor de AI inicializado")
        else:
            print("❌ Motor de AI não inicializado")
            return False
        
        return True
    except Exception as e:
        print(f"❌ Erro ao inicializar middleware: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_dataset_integration():
    """Testa funções de integração do dataset."""
    print("\n" + "="*70)
    print("  TEST 5: Integração do Dataset")
    print("="*70)
    
    try:
        from dataset_integration import (
            validate_dataset_pipeline_exists,
            validate_model_ready,
            MODEL_DIR,
            ML_CACHE_DIR
        )
        
        # Verificar estrutura
        if validate_dataset_pipeline_exists():
            print("✅ Pipeline de dataset encontrado")
        else:
            print("⚠ Pipeline de dataset não encontrado (OK se não foi executado ainda)")
        
        # Verificar modelo
        is_ready, missing = validate_model_ready()
        if is_ready:
            print("✅ Modelo está pronto")
        else:
            print(f"⚠ Modelo não pronto. Artefatos faltando:")
            for m in missing:
                print(f"   - {m}")
        
        print(f"   Diretório de modelo: {MODEL_DIR}")
        print(f"   Diretório de cache: {ML_CACHE_DIR}")
        
        return True
    except Exception as e:
        print(f"❌ Erro ao testar dataset integration: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """Executa todos os testes e retorna resultado final."""
    print("\n" + "="*70)
    print("  BATERIA DE TESTES - INTEGRAÇÃO WAFELL + DATASET")
    print("="*70)
    
    tests = [
        ("Estrutura de Arquivos", test_file_structure),
        ("Carregamento do Modelo", test_model_loading),
        ("Predição de Payloads", test_payload_prediction),
        ("Middleware", test_middleware_initialization),
        ("Dataset Integration", test_dataset_integration),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ Erro não capturado em {test_name}: {e}")
            results.append((test_name, False))
    
    # Resumo final
    print("\n" + "="*70)
    print("  RESUMO DOS TESTES")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSOU" if result else "❌ FALHOU"
        print(f"{status:12s} - {test_name}")
    
    print("\n" + "="*70)
    print(f"TOTAL: {passed}/{total} testes passaram")
    print("="*70 + "\n")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
