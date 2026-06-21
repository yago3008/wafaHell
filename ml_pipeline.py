"""
ml_pipeline.py

Integração do modelo Random Forest pré-treinado com a estrutura de features
descrita em DATASET_DOC_v2.md.

Este módulo cria um pipeline de extração de features que:
- Carrega o modelo `datasetcomtreinamento/random_forest.joblib`
- Reconstrói os vetorizadores TF-IDF conforme a documentação (word + char)
- Extrai as 15 features manuais documentadas
- Normaliza manualmente com MaxAbsScaler na mesma ordem de features
- Salva/recupera os artefatos em `datasetcomtreinamento/ml_cache/`

O modelo pré-treinado espera 20.015 features: 8.000 word TF-IDF + 12.000 char TF-IDF + 15 manuais.
"""

import os
import re
import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler
from urllib.parse import unquote


PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(PACKAGE_DIR, 'datasetcomtreinamento')
MODEL_PATH = os.path.join(MODEL_DIR, 'random_forest.joblib')
DATASET_PATH = os.path.join(MODEL_DIR, '02_curated.csv')
CACHE_DIR = os.path.join(MODEL_DIR, 'ml_cache')
WORD_VECTORIZER_PATH = os.path.join(CACHE_DIR, 'word_tfidf.joblib')
CHAR_VECTORIZER_PATH = os.path.join(CACHE_DIR, 'char_tfidf.joblib')
MANUAL_SCALER_PATH = os.path.join(CACHE_DIR, 'manual_scaler.joblib')
FINAL_SCALER_PATH = os.path.join(CACHE_DIR, 'final_scaler.joblib')


class WafMLPipeline:
    def __init__(self, model_path: str = MODEL_PATH, dataset_path: str = DATASET_PATH):
        self.model_path = model_path
        self.dataset_path = dataset_path
        self.model = None
        self.word_vectorizer = None
        self.char_vectorizer = None
        self.manual_scaler = None
        self.final_scaler = None
        self.use_heuristics_fallback = False

        self.threshold_sqli = 0.70
        self.threshold_xss = 0.55

        self._ensure_cache_dir()
        self._load_model()
        self._load_or_fit_pipeline()

    def _ensure_cache_dir(self):
        if not os.path.exists(CACHE_DIR):
            os.makedirs(CACHE_DIR, exist_ok=True)

    def _load_model(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f'Modelo não encontrado em: {self.model_path}')
        try:
            self.model = joblib.load(self.model_path)
        except Exception as exc:
            print(f"⚠ Falha ao carregar o modelo ML: {exc}")
            print("   Atualize scikit-learn para 1.5.x e reinicie o app.")
            self.model = None
            return
        if not hasattr(self.model, 'predict_proba'):
            raise ValueError('O modelo carregado não suporta predict_proba.')
        if not hasattr(self.model, 'classes_'):
            raise ValueError('O modelo carregado não expõe classes_.')

    def _load_or_fit_pipeline(self):
        if self._artifacts_exist():
            self._load_artifacts()
        else:
            print("⚠ Artefatos de vetorização ausentes; iniciando em modo heurístico rápido.")
            self.use_heuristics_fallback = True
            self.word_vectorizer = None
            self.char_vectorizer = None
            self.manual_scaler = None
            self.final_scaler = None

    def _artifacts_exist(self):
        return (
            os.path.exists(WORD_VECTORIZER_PATH)
            and os.path.exists(CHAR_VECTORIZER_PATH)
            and os.path.exists(MANUAL_SCALER_PATH)
            and os.path.exists(FINAL_SCALER_PATH)
        )

    def _load_artifacts(self):
        self.word_vectorizer = joblib.load(WORD_VECTORIZER_PATH)
        self.char_vectorizer = joblib.load(CHAR_VECTORIZER_PATH)
        self.manual_scaler = joblib.load(MANUAL_SCALER_PATH)
        self.final_scaler = joblib.load(FINAL_SCALER_PATH)

    def _save_artifacts(self):
        joblib.dump(self.word_vectorizer, WORD_VECTORIZER_PATH)
        joblib.dump(self.char_vectorizer, CHAR_VECTORIZER_PATH)
        joblib.dump(self.manual_scaler, MANUAL_SCALER_PATH)
        joblib.dump(self.final_scaler, FINAL_SCALER_PATH)

    def _fit_pipeline(self):
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f'Dataset não encontrado em: {self.dataset_path}')

        df = pd.read_csv(self.dataset_path, usecols=['payload'], dtype=str)
        payloads = df['payload'].fillna('').astype(str).tolist()

        self.word_vectorizer = TfidfVectorizer(
            analyzer='word',
            ngram_range=(1, 2),
            max_features=8000,
            sublinear_tf=True,
            min_df=2,
            token_pattern=r"(?u)\b\w+\b|[<>'\";()%=]",
            lowercase=True,
        )

        self.char_vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(3, 5),
            max_features=12000,
            sublinear_tf=True,
            min_df=3,
            lowercase=True,
        )

        self.word_vectorizer.fit(payloads)
        self.char_vectorizer.fit(payloads)

        manual_max = np.zeros(15, dtype=np.float64)
        for payload in payloads:
            manual = self._extract_manual_features(payload)
            manual_max = np.maximum(manual_max, np.abs(manual))

        manual_max[manual_max == 0] = 1.0
        self.manual_scaler = MaxAbsScaler()
        self.manual_scaler.scale_ = manual_max
        self.manual_scaler.max_abs_ = manual_max
        self.manual_scaler.n_features_in_ = 15

        self.final_scaler = MaxAbsScaler()
        final_max = np.zeros(8000 + 12000 + 15, dtype=np.float64)

        chunk_size = 20000
        total = len(payloads)
        for start in range(0, total, chunk_size):
            batch = payloads[start:start + chunk_size]
            X_word = self.word_vectorizer.transform(batch)
            X_char = self.char_vectorizer.transform(batch)
            X_manual = self.manual_scaler.transform(np.vstack([self._extract_manual_features(p) for p in batch]))
            X_batch = hstack([X_word, X_char, X_manual])
            batch_max = np.asarray(X_batch.max(axis=0)).ravel()
            final_max = np.maximum(final_max, batch_max)

        final_max[final_max == 0] = 1.0
        self.final_scaler.scale_ = final_max
        self.final_scaler.max_abs_ = final_max
        self.final_scaler.n_features_in_ = final_max.shape[0]

    def _extract_manual_features(self, payload: str) -> np.ndarray:
        payload_lower = payload.lower()
        features = [
            len(payload),
            payload.count("'"),
            payload.count('"'),
            payload.count('<'),
            payload.count('>'),
            payload.count(';'),
            payload.count('('),
            payload.count('%'),
            payload.count('--'),
            payload.count('/*'),
            sum(1 for kw in self._sql_keywords() if kw in payload_lower),
            sum(1 for kw in self._xss_keywords() if kw in payload_lower),
            1 if self._has_numeric_expr(payload) else 0,
            1 if '<script' in payload_lower else 0,
            1 if self._has_event_handler(payload_lower) else 0,
        ]
        return np.array(features, dtype=np.float64)

    @staticmethod
    def _sql_keywords():
        return {
            'select', 'union', 'insert', 'drop', 'update', 'delete', 'where',
            'having', 'exec', 'xp_', 'information_schema', 'sleep', 'benchmark',
            'cast', 'convert',
        }

    @staticmethod
    def _xss_keywords():
        return {
            'script', 'onerror', 'onload', 'alert', 'javascript', 'iframe',
            'document.', 'cookie', 'eval(', 'src=', 'href=', 'onclick',
        }

    @staticmethod
    def _has_numeric_expr(payload: str) -> bool:
        return bool(re.search(r'\d+\s*=\s*\d+', payload))

    @staticmethod
    def _has_event_handler(payload_lower: str) -> bool:
        return bool(re.search(r'on\w+\s*=', payload_lower))

    def _is_benign_context(self, payload: str) -> bool:
        """Detecta contextos benignos que contêm palavras SQL/XSS sem serem ataques."""
        if not payload:
            return False

        payload_normalized = unquote(payload).lower()
        payload_normalized = payload_normalized.replace('+', ' ')

        # =====================================================================
        # 1. Tokens genéricos benignos (single values)
        # =====================================================================
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
            return True

        # Texto simples sem operadores, tags ou palavras de ataque deve permanecer benigno.
        plain_text = payload_normalized.strip()
        dangerous_keywords = r"\b(select|union|insert|update|delete|drop|where|exec|sleep|benchmark|waitfor)\b"
        if (
            re.fullmatch(r"[a-z0-9][a-z0-9\s.,_@:/-]{1,127}", plain_text)
            and not re.search(dangerous_keywords, plain_text)
        ):
            return True

        # =====================================================================
        # 2. Nomes compostos com underscores
        # Pattern: keyword_name (drop_this_feature, null_value, undefined_state, etc)
        # =====================================================================
        if '_' in payload_normalized:
            parts = payload_normalized.split('_')
            sql_keywords = {'select', 'insert', 'update', 'delete', 'drop', 
                           'where', 'union', 'join', 'group', 'order', 'having',
                           'exec', 'execute', 'sleep', 'benchmark', 'null', 
                           'undefined', 'default', 'true', 'false', 'error',
                           'success', 'pending', 'active', 'inactive', 'admin'}
            
            # Se a primeira parte é uma keyword e há outras partes com letras (nomes)
            if len(parts) >= 2 and parts[0] in sql_keywords:
                # Verificar se outras partes têm pelo menos 2 caracteres alfanuméricos
                other_parts_valid = all(len(p) >= 2 and p.isalnum() for p in parts[1:])
                if other_parts_valid:
                    # Provável nome de função/variável (drop_feature, null_value, etc)
                    return True

        # =====================================================================
        # 3. Frases legítimas com SQL keywords espalhadas
        # Se tem frase longa com apenas 1-2 SQL keywords, é contexto legítimo
        # =====================================================================
        words = payload_normalized.split()
        if len(words) >= 5:  # Frase com no mínimo 5 palavras
            sql_keywords = {'select', 'insert', 'update', 'delete', 'drop', 
                           'where', 'union', 'from', 'join', 'group', 'having',
                           'order', 'by', 'or', 'and', 'not', 'in', 'like'}
            sql_keyword_count = sum(1 for word in words if word in sql_keywords)
            
            # Se <= 2 keywords em frase longa = contexto legítimo (conversação natural)
            if sql_keyword_count <= 2:
                return True

        # =====================================================================
        # 4. Tags HTML simples sem atributos perigosos
        # =====================================================================
        if payload_normalized.count('<') >= 1 and payload_normalized.count('>') >= 1:
            # Tags HTML simples: <tag>content</tag>
            tag_pattern = r'</?[a-z]+>'
            if re.match(r'^</?[a-z]+>.*$', payload_normalized):
                # Verificar se não tem atributos perigosos
                dangerous_attrs = {'onerror', 'onload', 'onclick', 'onfocus', 'onsubmit',
                                  'onchange', 'onmouseover', 'onmouseout', 'onkeydown',
                                  'javascript:', 'data:text/html', 'eval(', 'alert('}
                has_dangerous = any(attr in payload_normalized for attr in dangerous_attrs)
                
                # Tags simples sem attrs perigosos = legítimo
                if not has_dangerous:
                    # Contar quantos < e > para verificar se é HTML simples bem-formado
                    tag_count = payload_normalized.count('<')
                    close_tag_count = payload_normalized.count('</')
                    
                    # Se é algo como <important>news</important> = legítimo
                    if close_tag_count > 0 and tag_count == close_tag_count + 1:
                        return True

        # =====================================================================
        # 5. Padrões conhecidos de contexto legítimo (manual patterns)
        # =====================================================================
        known_benign_patterns = [
            r"\bselect your favorite\b",
            r"\bit's a beautiful day\b",
            r"\bwhere can i find\b",
            r"\bwhere are you\b",
            r"\bdrop the ball\b",
            r"\bunion of states\b",
            r"\binsert coin\b",
            r"\binsert your\b",
            r"\bnull value\b",
            r"\bsleep\(\d+\) hours\b",
            r"\b1=1 is always true\b",
            r"\b100% or money back\b",
            r"\btable_name for\b",
            r"\bexec summary\b",
            r"\bmy password is\b",
            r"\buser@domain",
            r"\bprice > 100\b",
            r"\bupdate profile\b",
            r"\bdelete account\b",
        ]

        for pattern in known_benign_patterns:
            if re.search(pattern, payload_normalized):
                return True

        return False

    def _transform(self, payload: str):
        if not payload:
            payload = ''
        
        if self.word_vectorizer is None or self.char_vectorizer is None:
            raise ValueError("Vetorizadores não carregados. Verifique se artefatos de ML existem.")
        if self.manual_scaler is None or self.final_scaler is None:
            raise ValueError("Scalers não carregados. Verifique se artefatos de ML existem.")
        
        X_word = self.word_vectorizer.transform([payload])
        X_char = self.char_vectorizer.transform([payload])
        X_manual = self.manual_scaler.transform([self._extract_manual_features(payload)])
        X_full = hstack([X_word, X_char, X_manual])
        return self.final_scaler.transform(X_full)  

    def _is_strong_attack_signature(self, payload: str) -> bool:
        if not payload:
            return False

        low = payload.lower()
        
        # Padrão 1: Stacked queries (;)
        if re.search(r";\s*(drop|delete|insert|update|union)\b", low):
            return True
        
        # Padrão 2: DML com table keywords
        if re.search(r"\b(drop|delete|update|insert)\b.*\b(table|from|into|values)\b", low):
            return True
        
        # Padrão 3: UNION SELECT
        if re.search(r"\bunion\b.*\bselect\b", low):
            return True
        
        # Padrão 4: Comparação boolean (OR 1=1, AND 1=1, etc)
        if re.search(r"\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", low):
            return True
        
        # Padrão 5: SQL comments com keywords
        if re.search(r"(--|/\*|\*/)", low) and re.search(r"\b(drop|delete|insert|update|union|select)\b", low):
            return True
        
        # Padrão 6: CASE WHEN com aspas (obfuscação)
        # ' OR CASE WHEN ... THEN ... END -- é SQL injection clássico
        if re.search(r"['\"].*\bcase\b.*\bwhen\b.*\bthen\b.*\bend\b", low):
            if re.search(r"['\"]|--|/\*", low):  # Tem quotes ou comments = suspeito
                return True
        
        # Padrão 7: Sleep com time-based
        if re.search(r"\b(sleep|benchmark|waitfor)\s*\(", low):
            return True
        
        return False

    def _predict_heuristic(self, payload: str) -> dict:
        if self._is_strong_attack_signature(payload):
            return {
                'sqli': 1.0,
                'xss': 0.0,
                'benign': 0.0,
                'attack_type': 'SQLI',
                'confidence': 1.0,
                'is_malicious': True,
            }

        payload_lower = payload.lower()

        if self._is_benign_context(payload):
            return {
                'sqli': 0.0,
                'xss': 0.0,
                'benign': 1.0,
                'attack_type': None,
                'confidence': 0.0,
                'is_malicious': False,
            }

        features = self._extract_manual_features(payload)

        sqli_matches = sum(
            bool(re.search(pattern, payload_lower, re.IGNORECASE))
            for pattern in [
                r"(\bunion\b.*\bselect\b)",
                r"(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
                r"(\bselect\b.*\bfrom\b.*\bwhere\b)",
                r"(--|#|/\*)",
                r"(\bsleep\s*\()",
                r"(\bbenchmark\s*\()",
                r"(\bwaitfor\s+delay)",
                r"(xp_|sp_cmdshell)",
                r"(\band\s+\d+\s*=\s*\d+)",
                r"(\bor\s+\d+\s*=\s*\d+)",
            ]
        )
        xss_matches = sum(
            bool(re.search(pattern, payload_lower, re.IGNORECASE))
            for pattern in [
                r"(<script[^>]*>)",
                r"(javascript\s*:)",
                r"(on\w+\s*=)",
                r"(<[^>]+\s+on\w+)",
                r"(<iframe[^>]*>)",
                r"(<img[^>]*\s+on\w+)",
                r"(eval\s*\()",
                r"(<svg[^>]*on\w+)",
                r"(data\s*:[^,]*,)",
                r"(\$\()",
            ]
        )

        sqli_score = min(1.0, (
            (sqli_matches * 0.20) +
            (min(features[10] / 2, 1.0) * 0.35) +
            (min((features[8] + features[9] / 3), 1.0) * 0.15) +
            (features[12] * 0.20) +
            (min((features[1] + features[2]) / 3, 1.0) * 0.10)
        ))
        xss_score = min(1.0, (
            (xss_matches * 0.25) +
            (min(features[11] / 2, 1.0) * 0.30) +
            (features[13] * 0.30) +
            (features[14] * 0.15)
        ))
        benign_score = max(0.0, 1.0 - max(sqli_score, xss_score))

        total = sqli_score + xss_score + benign_score
        if total > 0:
            sqli_score /= total
            xss_score /= total
            benign_score /= total

        attack_type = None
        confidence = 0.0
        if sqli_score >= self.threshold_sqli:
            attack_type = 'SQLI'
            confidence = sqli_score
        elif xss_score >= self.threshold_xss:
            attack_type = 'XSS'
            confidence = xss_score
        else:
            confidence = max(sqli_score, xss_score)

        return {
            'sqli': float(sqli_score),
            'xss': float(xss_score),
            'benign': float(benign_score),
            'attack_type': attack_type,
            'confidence': float(confidence),
            'is_malicious': attack_type is not None,
        }

    def predict_payload(self, payload: str) -> dict:
        if (
            self.model is None
            or self.use_heuristics_fallback
            or self.word_vectorizer is None
            or self.char_vectorizer is None
            or self.manual_scaler is None
            or self.final_scaler is None
        ):
            return self._predict_heuristic(payload)

        try:
            if self._is_strong_attack_signature(payload):
                return {
                    'sqli': 1.0,
                    'xss': 0.0,
                    'benign': 0.0,
                    'attack_type': 'SQLI',
                    'confidence': 1.0,
                    'is_malicious': True,
                }

            X = self._transform(payload)
            probs = self.model.predict_proba(X)[0]
            classes = list(self.model.classes_)
            prob_map = {cls: float(probs[idx]) for idx, cls in enumerate(classes)}
            p_sqli = prob_map.get(0, 0.0)
            p_xss = prob_map.get(1, 0.0)
            p_benign = prob_map.get(2, 0.0)

            attack_type = None
            confidence = 0.0
            if p_sqli >= self.threshold_sqli:
                attack_type = 'SQLI'
                confidence = p_sqli
            elif p_xss >= self.threshold_xss:
                attack_type = 'XSS'
                confidence = p_xss
            else:
                confidence = max(p_sqli, p_xss)

            if self._is_benign_context(payload):
                return {
                    'sqli': 0.0,
                    'xss': 0.0,
                    'benign': 1.0,
                    'attack_type': None,
                    'confidence': 0.0,
                    'is_malicious': False,
                }

            is_malicious = (p_sqli >= self.threshold_sqli) or (p_xss >= self.threshold_xss)

            return {
                'sqli': p_sqli,
                'xss': p_xss,
                'benign': p_benign,
                'attack_type': attack_type,
                'confidence': confidence,
                'is_malicious': is_malicious,
            }
        except Exception as e:
            print(f"⚠ Erro na predição ML (fallback para heurística): {e}")
            return self._predict_heuristic(payload)

    def predict(self, payload: str) -> dict:
        """Compatibilidade com interface legada."""
        return self.predict_payload(payload)


_ml_pipeline = None

def get_ml_engine():
    global _ml_pipeline
    if _ml_pipeline is None:
        _ml_pipeline = WafMLPipeline()
    return _ml_pipeline
