"""
dataset_integration.py — Integração do pipeline de dataset com o WAF.

Este módulo facilita o treino de modelos de ML usando o pipeline 
em dataset_pipeline/ e integra os artefatos gerados com ml_pipeline.py.

Funções principais:
- run_training_pipeline(): Executa todo o pipeline (01 a 05)
- export_model_artifacts(): Copia artefatos para o diretório correto
- validate_model_ready(): Verifica se o modelo está pronto para uso
"""

import os
import sys
import subprocess
import shutil
import joblib
import warnings
from pathlib import Path
from typing import Tuple

warnings.filterwarnings("ignore")

BASE_DIR = Path(__file__).parent
DATASET_PIPELINE_DIR = BASE_DIR.parent / "dataset_pipeline"
ML_CACHE_DIR = BASE_DIR / "datasetcomtreinamento" / "ml_cache"
MODEL_DIR = BASE_DIR / "datasetcomtreinamento"


def validate_dataset_pipeline_exists() -> bool:
    """Verifica se o pipeline de dataset existe no local esperado."""
    required_files = [
        DATASET_PIPELINE_DIR / "01_collect.py",
        DATASET_PIPELINE_DIR / "02_curate.py",
        DATASET_PIPELINE_DIR / "03_features.py",
        DATASET_PIPELINE_DIR / "04_train_validate.py",
        DATASET_PIPELINE_DIR / "05_fp_analysis.py",
    ]
    
    missing = [f for f in required_files if not f.exists()]
    if missing:
        print(f"⚠ Arquivos do pipeline ausentes:")
        for f in missing:
            print(f"  - {f}")
        return False
    return True


def run_training_pipeline(python_exe: str | None = None) -> bool:
    """
    Executa o pipeline de treinamento completo (estágios 1-5).
    
    Args:
        python_exe: Executável Python a usar. Se None, usa o interpretador atual.
    
    Returns:
        True se bem-sucedido, False caso contrário.
    """
    if python_exe is None:
        python_exe = sys.executable
    if not validate_dataset_pipeline_exists():
        print("❌ Pipeline de dataset não encontrado!")
        return False
    
    print("\n" + "=" * 70)
    print("  INICIANDO PIPELINE DE TREINAMENTO")
    print("=" * 70)
    
    try:
        # Executa o run_pipeline.sh via subprocess
        pipeline_script = DATASET_PIPELINE_DIR / "run_pipeline.sh"
        
        # No Windows, usa .bat se disponível; caso contrário, tenta com bash
        if sys.platform == "win32":
            # Tenta executar os scripts Python diretamente
            stages = [
                ("01_collect.py", "Coleta de Dados"),
                ("02_curate.py", "Curadoria de Dataset"),
                ("03_features.py", "Extração de Features"),
                ("04_train_validate.py", "Treinamento e Validação"),
                ("05_fp_analysis.py", "Análise de Falsos Positivos"),
            ]
            
            for script, description in stages:
                script_path = DATASET_PIPELINE_DIR / script
                print(f"\n{'='*70}")
                print(f"  Executando: {description} ({script})")
                print('='*70)
                
                result = subprocess.run(
                    [python_exe, str(script_path)],
                    cwd=str(DATASET_PIPELINE_DIR),
                    capture_output=False
                )
                
                if result.returncode != 0:
                    print(f"❌ {script} falhou (exit code {result.returncode})")
                    return False
                print(f"✅ {script} concluído")
        else:
            # Unix/Linux
            result = subprocess.run(
                ["bash", str(pipeline_script)],
                cwd=str(DATASET_PIPELINE_DIR)
            )
            if result.returncode != 0:
                print(f"❌ Pipeline falhou (exit code {result.returncode})")
                return False
        
        print("\n" + "=" * 70)
        print("  ✅ PIPELINE CONCLUÍDO COM SUCESSO")
        print("=" * 70)
        return True
        
    except Exception as e:
        print(f"❌ Erro ao executar pipeline: {e}")
        return False


def export_model_artifacts() -> bool:
    """
    Copia os artefatos do modelo gerado pelo pipeline para o local esperado 
    pelo ml_pipeline.py (datasetcomtreinamento/ml_cache/).
    
    Artefatos esperados:
    - models/random_forest.joblib
    - models/word_tfidf.joblib
    - models/char_tfidf.joblib
    - models/feature_scaler.joblib
    
    Returns:
        True se bem-sucedido, False caso contrário.
    """
    print("\n" + "=" * 70)
    print("  EXPORTANDO ARTEFATOS DE MODELO")
    print("=" * 70)
    
    pipeline_models_dir = DATASET_PIPELINE_DIR / "models"
    
    if not pipeline_models_dir.exists():
        print(f"⚠ Diretório de modelos não encontrado: {pipeline_models_dir}")
        print("  Certifique-se de ter executado o pipeline primeiro.")
        return False
    
    # Cria o diretório de cache se não existir
    ML_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    artifacts = {
        "random_forest.joblib": "Modelo Random Forest",
        "word_tfidf.joblib": "Vetorizador TF-IDF (word)",
        "char_tfidf.joblib": "Vetorizador TF-IDF (char)",
        "manual_scaler.joblib": "Scaler manual",
        "final_scaler.joblib": "Scaler final",
    }
    
    alt_names = {
        # O pipeline salva feature_scaler.joblib, mas o app espera final_scaler.joblib
        "final_scaler.joblib": ["feature_scaler.joblib"],
    }
    
    all_success = True
    for filename, description in artifacts.items():
        src = pipeline_models_dir / filename
        
        # Se não encontrar com o nome padrão, tenta alternativas
        if not src.exists() and filename in alt_names:
            for alt_name in alt_names[filename]:
                alt_src = pipeline_models_dir / alt_name
                if alt_src.exists():
                    src = alt_src
                    break
        
        dst = ML_CACHE_DIR / filename
        
        if src.exists():
            try:
                shutil.copy2(src, dst)
                print(f"✅ {filename:30s} → {description}")
            except Exception as e:
                print(f"❌ Erro ao copiar {filename}: {e}")
                all_success = False
        else:
            print(f"⚠ {filename:30s} não encontrado")
            all_success = False
    
    # Também copia o modelo Random Forest para o diretório principal se existir
    rf_src = pipeline_models_dir / "random_forest.joblib"
    rf_dst = MODEL_DIR / "random_forest.joblib"
    if rf_src.exists():
        try:
            shutil.copy2(rf_src, rf_dst)
            print(f"✅ Modelo salvo em: {rf_dst}")
        except Exception as e:
            print(f"⚠ Erro ao copiar modelo para diretório principal: {e}")
    
    return all_success


def validate_model_ready() -> Tuple[bool, list]:
    """
    Verifica se o modelo está pronto para uso (todos os artefatos presentes).
    
    Returns:
        (is_ready: bool, missing_artifacts: list)
    """
    required_files = [
        ML_CACHE_DIR / "word_tfidf.joblib",
        ML_CACHE_DIR / "char_tfidf.joblib",
        ML_CACHE_DIR / "manual_scaler.joblib",
        ML_CACHE_DIR / "final_scaler.joblib",
        MODEL_DIR / "random_forest.joblib",
    ]
    
    missing = [f for f in required_files if not f.exists()]
    
    if not missing:
        print("✅ Modelo pronto para uso (todos os artefatos presentes)")
        return True, []
    else:
        print("⚠ Artefatos de modelo ausentes:")
        for f in missing:
            print(f"  - {f}")
        return False, missing


def check_model_integrity() -> bool:
    """
    Valida que os artefatos carregáveis sem corrupção.
    
    Returns:
        True se íntegros, False caso contrário.
    """
    print("\n" + "=" * 70)
    print("  VALIDANDO INTEGRIDADE DO MODELO")
    print("=" * 70)
    
    artifacts = {
        ML_CACHE_DIR / "random_forest.joblib": "Modelo",
        ML_CACHE_DIR / "word_tfidf.joblib": "Vetorizador (word)",
        ML_CACHE_DIR / "char_tfidf.joblib": "Vetorizador (char)",
        ML_CACHE_DIR / "manual_scaler.joblib": "Scaler (manual)",
        ML_CACHE_DIR / "final_scaler.joblib": "Scaler (final)",
    }
    
    all_valid = True
    for path, name in artifacts.items():
        if not path.exists():
            print(f"⚠ {name:25s} - arquivo não encontrado: {path}")
            all_valid = False
            continue
        
        try:
            obj = joblib.load(str(path))
            print(f"✅ {name:25s} - OK (tipo: {type(obj).__name__})")
        except Exception as e:
            print(f"❌ {name:25s} - CORRUPÇÃO: {e}")
            all_valid = False
    
    return all_valid


def print_status_report():
    """Imprime um relatório de status do modelo."""
    print("\n" + "=" * 70)
    print("  RELATÓRIO DE STATUS DO MODELO")
    print("=" * 70)
    
    is_ready, missing = validate_model_ready()
    
    if is_ready:
        print("Status: ✅ PRONTO PARA PRODUÇÃO\n")
        check_model_integrity()
    else:
        print("Status: ⚠ NÃO PRONTO\n")
        print("Ações recomendadas:")
        print("1. Executar: dataset_integration.run_training_pipeline()")
        print("2. Executar: dataset_integration.export_model_artifacts()")
        print("3. Verificar: dataset_integration.check_model_integrity()")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "train":
            if run_training_pipeline():
                export_model_artifacts()
                print_status_report()
            sys.exit(0 if validate_model_ready()[0] else 1)
        
        elif command == "export":
            if export_model_artifacts():
                check_model_integrity()
            sys.exit(0)
        
        elif command == "validate":
            is_ready, _ = validate_model_ready()
            if is_ready:
                check_model_integrity()
            sys.exit(0 if is_ready else 1)
        
        elif command == "status":
            print_status_report()
            sys.exit(0)
        
        else:
            print(f"Comando desconhecido: {command}")
            print("Comandos disponíveis: train, export, validate, status")
            sys.exit(1)
    else:
        print("Dataset Integration para WafaHell")
        print("Uso: python dataset_integration.py [comando]")
        print("\nComandos:")
        print("  train    - Executar pipeline completo (01-05)")
        print("  export   - Copiar artefatos para ml_cache/")
        print("  validate - Validar integridade do modelo")
        print("  status   - Exibir status do modelo")
        sys.exit(0)
