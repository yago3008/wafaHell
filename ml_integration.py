"""
ml_integration.py — Wrapper de compatibilidade para o motor de ML principal.

Este arquivo mantém a mesma API de importação usada por scripts de teste
legados e redireciona toda a lógica para o módulo `ml_pipeline.py`.
"""

try:
    from ml_pipeline import get_ml_engine
except ImportError:
    from .ml_pipeline import get_ml_engine
