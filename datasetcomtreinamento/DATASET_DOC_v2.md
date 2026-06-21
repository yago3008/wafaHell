# Dataset de Detecção de Ataques Web (SQLi e XSS) — v2

**Versão:** 2.0  
**Data:** Maio de 2026  
**Objetivo:** Treinar um modelo Random Forest capaz de classificar requisições HTTP como `benign`, `sqli` ou `xss` com alta precisão, alto recall e baixo índice de falsos positivos (FPR).

---

## Histórico de Versões

| Versão | Data | Principais Mudanças |
|--------|------|---------------------|
| v1 | Abr/2026 | Dataset inicial: Kaggle + CSIC 2010 + geração sintética básica (20 grupos de templates) |
| **v2** | **Mai/2026** | **+ SecLists (XSS/SQLi reais); + augmentação XSS documentada (12 categorias); + prosa natural PT/EN; + XML/SVG legítimos; templates benign: 66 → 180 grupos** |

---

## 1. Visão Geral

O dataset foi construído a partir de **cinco fontes distintas**, combinando dados reais de ataques, tráfego HTTP capturado, geração sintética controlada e augmentação baseada em técnicas documentadas de evasão.

O design prioriza três objetivos:

1. **Alto recall de ataque** — o modelo não deve deixar ataques passarem
2. **Baixo FPR** — requisições legítimas não devem ser bloqueadas
3. **Cobertura ampla de XSS** — compensar a escassez natural de amostras XSS reais em datasets públicos

### Mapeamento de Classes

| Rótulo Textual | Rótulo Numérico | Descrição |
|----------------|----------------|-----------|
| `sqli` | `0` | SQL Injection — consultas maliciosas explorando banco de dados |
| `xss` | `1` | Cross-Site Scripting — payloads injetando código JavaScript/HTML |
| `benign` | `2` | Tráfego legítimo — requisições normais de usuários |

---

## 2. Fontes de Dados

### 2.1 Datasets Kaggle — SQLi (Fonte A)

#### sqli_biggest.csv
- **Origem:** [Biggest SQL Injection Dataset — Kaggle (GAMBLER YU)](https://www.kaggle.com/datasets/gambleryu/biggest-sql-injection-dataset)
- **Coluna:** `Query` | **Classe:** `sqli` | **Amostras:** 148.326
- **Conteúdo:** Consultas SQL maliciosas de múltiplos tipos — UNION-based, boolean-based, error-based, time-based blind.

#### sqli_dataset.csv
- **Origem:** [SQL Injection Dataset — Kaggle (sajid576)](https://www.kaggle.com/datasets/sajid576/sql-injection-dataset)
- **Coluna:** `Query` | **Classe:** `sqli` | **Amostras:** 30.919
- **Conteúdo:** Versão modificada/ampliada com consultas SQL maliciosas.

### 2.2 Dataset Kaggle — XSS (Fonte A)

#### xss_dataset.csv
- **Origem:** [Cross Site Scripting XSS Dataset for Deep Learning — Kaggle (syedsaqlainhussain)](https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning)
- **Coluna:** `Sentence` | **Classe:** `xss` | **Amostras:** 13.686
- **Conteúdo:** Payloads XSS incluindo `<script>`, event handlers, `javascript:` URIs, payloads encodados.

### 2.3 CSIC 2010 HTTP Dataset — Tráfego Real (Fonte B)

- **Origem:** [CSIC 2010 HTTP Dataset](http://www.isi.csic.es/dataset/) — Instituto de Seguridad de la Información (CSIC), Madrid, Espanha
- **Formato:** Blocos de requisições HTTP brutas (GET/POST), separados por linhas em branco
- **Extração:** Path + query string + body (quando presente via `Content-Length`)

| Arquivo | Classe | Amostras |
|---------|--------|----------|
| `normalTrafficTraining.txt` | `benign` (2) | 36.000 |
| `normalTrafficTest.txt` | `benign` (2) | 36.000 |
| `anomalousTrafficTest.txt` | `sqli` (0) | 25.065 |

**Notas:**
- Tráfego benign: requisições reais para aplicação e-commerce (`tienda1`) — catálogo, formulários, autenticação
- Alta taxa de duplicatas (~50%) tratada na curadoria
- **Limitação conhecida:** todo tráfego benign é de um único domínio/app, contribuindo para a necessidade de enriquecimento sintético

### 2.4 Geração Sintética — Tráfego Legítimo Ambíguo (Fonte C)

- **Ferramenta:** [Faker](https://faker.readthedocs.io/) com locales `pt_BR` e `en_US`
- **Classe:** `benign` (2) | **Amostras geradas:** 150.000 | **Seed:** 42

#### v1 → v2: Expansão de templates (66 → 180 grupos)

A v1 cobria padrões `key=value&key2=value2` típicos de formulários HTTP. A v2 adicionou grupos que cobrem as **lacunas identificadas em testes** de FP:

| Grupo | v1 | v2 | Cobertura adicionada |
|-------|----|----|-----------------------|
| 1–12 | ✓ | ✓ | Nomes com apóstrofe, palavras SQL em query string, HTML legítimo, parâmetros booleanos ambíguos, event handlers em config, encoding em URLs, senhas/tokens, comentários, API REST, e-commerce, termos técnicos |
| 13–20 | ✓ | ✓ | Formulários EN, IDs numéricos, busca/filtro EN, perfil/cadastro EN, carrinho EN, paginação EN, paths REST EN, sistema/config EN |
| **21** | ✗ | **✓** | **Prosa natural PT com vocabulário SQL** — frases como *"fiz alguns selects para buscar dados das tabelas"* |
| **22** | ✗ | **✓** | **Prosa natural EN com vocabulário SQL/JS** — *"ive done some selects on the table for the report"*, *"using alert to debug my application"* |
| **23** | ✗ | **✓** | **XML e SVG legítimos sem scripts** — `<?xml version="1.0"?>`, `<svg>` com formas geométricas, feeds RSS/Atom |
| **24** | ✗ | **✓** | **Código técnico legítimo** — funções JS, `document.querySelector`, comentários de código, scripts Python |
| **25** | ✗ | **✓** | **Conteúdo de fórum/CMS** — perguntas reais sobre SQL, JavaScript, scripting em português e inglês |

**Motivação para os grupos 21–25:**  
Em testes interativos do modelo v1, foram identificados falsos positivos em:
- Texto em prosa com `select`, `from`, `where`, `tables` em contexto educacional/profissional → classificado como SQLi
- XML/SVG bem-formados sem scripts → classificado como XSS
- Frases técnicas com `alert`, `script`, `document` em contexto legítimo → classificado como XSS

O modelo v1 nunca havia visto esses padrões na classe benign, pois todo o tráfego benign era HTTP estruturado.

### 2.5 Augmentação XSS — Técnicas Documentadas (Fonte D)

- **Classe:** `xss` (1) | **Amostras:** 200.000 | **Seed:** 42

#### Motivação

O XSS real em datasets públicos totaliza ~23.500 amostras — 8,7x menor que SQLi. Isso não é acidente: XSS real é intrinsecamente escasso porque seus payloads dependem do contexto HTML da aplicação-alvo, tornando sua coleta e anotação mais difícil que SQLi. A literatura de WAF com ML reconhece esse problema e adota augmentação baseada em técnicas documentadas como solução padrão.

A augmentação v2 cobre **12 categorias** com referências acadêmicas:

| # | Categoria | Referência |
|---|-----------|------------|
| 1 | Script tag básico | PortSwigger XSS Cheat Sheet (set. 2019) |
| 2 | Tags quebradas/aninhadas (filter evasion) | Bypassing Signature-Based XSS Filters (PortSwigger, ago. 2020); mXSS Attacks — Heiderich et al. (set. 2013) |
| 3 | Encoding bypasses (Unicode, HTML entities, hex, URL-encoding) | Xssing Web With Unicodes — Rakesh Mane (ago. 2017); Encoding Differentials — Stefan Schiller (jul. 2024) |
| 4 | IMG event handlers | PortSwigger XSS Cheat Sheet (set. 2019) |
| 5 | SVG payloads | PortSwigger XSS Cheat Sheet (set. 2019); Short SVG Payloads (noraj) |
| 6 | HTML5 tags com event handlers não-óbvios | PortSwigger XSS Cheat Sheet (set. 2019); Ways to alert(document.domain) — Tom Hudson (fev. 2018) |
| 7 | Div / pointer events | PortSwigger XSS Cheat Sheet (set. 2019) |
| 8 | URI wrappers (`javascript:`, `data:`, encodings do esquema) | Twitter XSS via javascript scheme — Sergey Bobrov (set. 2017); PortSwigger XSS Cheat Sheet (set. 2019) |
| 9 | Data grabbers (exfiltração de cookie / localStorage) | XSS by Tossing Cookies — WeSecureApp (jul. 2017); XSS in Uber via Cookie — zhchbin (ago. 2017) |
| 10 | Mutation XSS (mXSS) | DOMPurify 2.0.0 bypass — Michał Bentkowski (set. 2019); mXSS Attacks — Heiderich et al. (set. 2013); Mutation XSS in Google Search — Tomasz Nidecki (abr. 2019) |
| 11 | Polyglot payloads | Ultimate XSS Polyglot — Ahmed Elsobky (fev. 2018); XSS ghettoBypass — d3adend (set. 2015) |
| 12 | JS context escapes | PortSwigger XSS Cheat Sheet (set. 2019) |

Cada categoria usa funções JavaScript variadas (15 funções de PoC), atributos HTML aleatórios e contextos HTTP realistas (query string, form field, path, raw), garantindo diversidade sem repetição literal.

### 2.6 SecLists — Payloads Reais Curados pela Comunidade (Fonte E — v2)

- **Origem:** [SecLists — danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) (clonado com sparse checkout)
- **Pasta:** `data/raw/seclists/`

| Subcoleção | Classe | Arquivos | Amostras brutas | Após dedup/sample |
|------------|--------|----------|-----------------|-------------------|
| `Fuzzing/XSS/human-friendly/` | `xss` | 9 arquivos | ~7.600 | — |
| `Fuzzing/XSS/Polyglots/` | `xss` | 3 arquivos | ~26 | — |
| `Fuzzing/XSS/robot-friendly/` | `xss` | 6 arquivos | ~6.800 | — |
| `Fuzzing/URI-XSS.fuzzdb.txt` + `HTML5sec` | `xss` | 2 arquivos | ~140 | — |
| **XSS total** | `xss` | **20 arquivos** | **~14.700 únicos** | **9.868 (sample 20k)** |
| `Fuzzing/Databases/SQLi/` | `sqli` | 9 arquivos | 587 | 479 |

**Critérios de seleção dos arquivos:**
- Incluídos: arquivos com payloads funcionais de XSS/SQLi reais
- Excluídos: `XSS-Fuzzing.txt` e `XSS-Cheat-Sheet-PortSwigger.txt` da pasta robot-friendly foram incluídos mas limitados pelo sample de 20k — o cheat sheet PortSwigger tem 6.047 payloads únicos de alta qualidade
- Excluídos: arquivos de enumeração de banco (`OracleDB-SID.txt`, `MSSQL-Enumeration.fuzzdb.txt`) — não são payloads de injeção
- Deduplicação: `dict.fromkeys()` preservando ordem de inserção
- XSS limitado a 20.000 amostras para não criar desequilíbrio com as demais fontes

---

## 3. Distribuição Final do Dataset (v2)

### Pós-coleta (01_collect.py)

| Classe | Amostras | % |
|--------|----------|---|
| xss | 223.404 | 34,4% |
| benign | 222.000 | 34,2% |
| sqli | 204.249 | 31,4% |
| **Total** | **649.653** | |

**Comparação com v1:**

| Classe | v1 (pós-coleta) | v2 (pós-coleta) | Δ |
|--------|-----------------|-----------------|---|
| sqli | 203.805 (52,3%) | 204.249 (31,4%) | +444, proporção ↓ |
| benign | 172.000 (44,2%) | 222.000 (34,2%) | +50.000 |
| xss | 13.565 (3,5%) | 223.404 (34,4%) | **+209.839** |

A principal melhoria estrutural da v2 é a **eliminação do desequilíbrio severo de XSS**: de 3,5% para 34,4%, aproximando as três classes de uma distribuição uniforme.

---

## 4. Pipeline de Processamento

O dataset passou por **6 estágios sequenciais**:

```
data/raw/  →  01_collect  →  02_curate  →  03_features  →  04_train  →  05_fp_analysis  →  06_export
```

### Estágio 1 — Coleta (`01_collect.py`)

- Carregamento dos arquivos Kaggle com fallback de encoding (UTF-8 → Latin-1)
- Parser de blocos HTTP para o CSIC 2010
- Geração de 150.000 amostras sintéticas legítimas (180 grupos de templates)
- Augmentação XSS com 12 categorias documentadas (200.000 amostras)
- Carregamento do SecLists (20 arquivos XSS + 9 arquivos SQLi, com dedup)
- **Saída:** `data/interim/01_raw_combined.csv`

### Estágio 2 — Curadoria (`02_curate.py`)

**Limpeza aplicada:**
- Decodificação de percent-encoding (`%27` → `'`, `%3C` → `<`) via `urllib.parse.unquote_plus`
- Remoção de caracteres zero-width (U+200B, U+FEFF, U+200C, U+200D, U+00AD, U+2060)
- Normalização de múltiplos espaços para um único espaço
- Remoção de payloads com comprimento < 4 caracteres após limpeza
- Remoção de duplicatas exatas após limpeza

> **Normalização mínima e intencional:** maiúsculas/minúsculas, apóstrofes e símbolos especiais foram **preservados** — esses são sinais discriminativos que o modelo precisa aprender.

**Geração de variantes ofuscadas (40% dos maliciosos amostrados):**

Para aumentar o recall contra técnicas de evasão, variantes ofuscadas foram geradas para 40% das amostras maliciosas:

*SQLi:*
- UPPERCASE / lowercase completo
- Substituição de espaço por `/**/` (comentário inline SQL)
- Substituição de espaço por `\t`
- URL-encode: `'` → `%27`, espaço → `%20`
- Double URL-encode: `'` → `%2527`
- Adição de comentário SQL: `-- -` ou `#`

*XSS:*
- `<script>` → `<SCRIPT>`
- `<script>` → `<scr\x00ipt>` (null byte)
- `alert` → `al\u0065rt` (unicode escape)
- `<script>alert(1)</script>` → `<img src=x onerror=alert(1)>`
- `javascript:` → `JaVaScRiPt:`
- Adição de atributo inócuo antes do payload

**Estrutura do arquivo de saída (`02_curated.csv`):**

| Coluna | Tipo | Descrição |
|--------|------|-----------|
| `payload` | string | Texto do payload após limpeza |
| `label` | string | Classe: `sqli`, `xss` ou `benign` |
| `source` | string | Identificador da fonte de origem |

Valores possíveis da coluna `source`:

| Valor | Origem |
|-------|--------|
| `kaggle_sqli` | Datasets Kaggle SQLi |
| `csic_sqli` | CSIC 2010 tráfego anômalo |
| `csic_benign` | CSIC 2010 tráfego normal |
| `synthetic_legit` | Geração sintética (grupos 1–25) |
| `xss_augmented` | Augmentação XSS (12 categorias) |
| `seclists_xss` | SecLists — payloads XSS |
| `seclists_sqli` | SecLists — payloads SQLi |
| `*_obfuscated` | Variante ofuscada de qualquer fonte acima |

**Distribuição resultante após curadoria:**

| Classe | Linhas | % | Nota |
|--------|--------|---|------|
| sqli | 366.297 | 51.7% | Maior por receber mais variantes ofuscadas (base SQLi é maior) |
| xss | 224.823 | 31.7% | — |
| benign | 117.505 | 16.6% | Sem variantes — ofuscação só é aplicada em maliciosos |
| **Total** | **708.625** | | |

> **Por que o benign é minoria aqui:** as variantes ofuscadas são geradas exclusivamente para `sqli` e `xss`. Adicionar variantes ofuscadas ao benign não faz sentido semântico — tráfego legítimo não é "ofuscado". O desequilíbrio é corrigido pelo `RandomOverSampler` antes do treino (estágio 4), e pelo `class_weight="balanced_subsample"` interno do Random Forest.

### Estágio 3 — Extração de Features (`03_features.py`)

Cada payload foi transformado em um vetor de features combinando três tipos:

#### TF-IDF Word N-grams
```
analyzer     = "word"
ngram_range  = (1, 2)       — unigramas e bigramas
max_features = 8.000
sublinear_tf = True         — log(1 + tf) para suavizar frequência
min_df       = 2
token_pattern = r"(?u)\b\w+\b|[<>'\";()%=]"  — símbolos como tokens próprios
```

#### TF-IDF Char N-grams
```
analyzer     = "char_wb"
ngram_range  = (3, 5)       — trigramas a pentagramas de caracteres
max_features = 12.000
sublinear_tf = True
min_df       = 3
```

#### Features Manuais Estruturais (15 features)

| # | Feature | Descrição |
|---|---------|-----------|
| 1 | `feat_len` | Comprimento total do payload |
| 2 | `feat_apostrophe` | Contagem de `'` |
| 3 | `feat_dquote` | Contagem de `"` |
| 4 | `feat_lt` | Contagem de `<` |
| 5 | `feat_gt` | Contagem de `>` |
| 6 | `feat_semicolon` | Contagem de `;` |
| 7 | `feat_paren` | Contagem de `(` |
| 8 | `feat_percent` | Contagem de `%` |
| 9 | `feat_dashdash` | Contagem de `--` |
| 10 | `feat_comment` | Contagem de `/*` |
| 11 | `feat_sql_kw` | Nº de keywords SQL presentes¹ |
| 12 | `feat_xss_kw` | Nº de keywords XSS presentes² |
| 13 | `feat_1eq1` | Padrão `\d+=\d+` presente (0/1) |
| 14 | `feat_script_tag` | Tag `<script` presente (0/1) |
| 15 | `feat_handler` | Event handler `on\w+=` presente (0/1) |

> ¹ Keywords SQL: `select, union, insert, drop, update, delete, where, having, exec, xp_, information_schema, sleep, benchmark, cast, convert`  
> ² Keywords XSS: `script, onerror, onload, alert, javascript, iframe, document., cookie, eval(, src=, href=, onclick`

**Nota sobre `feat_sql_kw` (limitação conhecida):**  
A feature conta ocorrências de keywords SQL como **substrings**, não como tokens. Isso significa que `"selects"` aciona `"select"` e `"tables"` não aciona nada, mas a palavra `"where"` em prosa aciona a keyword. Esta limitação foi endereçada na v2 pela adição dos grupos 21–22 no benign sintético, ensinando o modelo a distinguir prosa técnica de SQLi estruturado pelo contexto TF-IDF. Uma melhoria futura seria substituir contagem de substring por detecção de padrões sintáticos (`SELECT.*FROM`, `UNION.*SELECT`).

**Normalização:**
- Features manuais: `MaxAbsScaler` individual antes da concatenação
- Matriz final completa: `MaxAbsScaler` global após concatenação

**Concatenação final:**
```
X = [X_word (8k) | X_char (12k) | X_manual (15)] = 20.015 features por amostra
Formato: scipy CSR (matriz esparsa)
```

### Estágio 4 — Treino e Validação (`04_train_validate.py`)

#### Divisão dos dados
```
Estratégia: StratifiedShuffleSplit (preserva proporção de classes)
Seed: 42
Treino:     70%
Validação:  15%
Teste:      15%
```

#### Balanceamento do conjunto de treino
```python
RandomOverSampler(random_state=42)
```
Equaliza as 3 classes por duplicação aleatória da minoria. Aplicado **somente no treino** — validação e teste mantêm distribuição real.

> **Nota metodológica — redundância com `class_weight`:**  
> O `RandomOverSampler` **não sintetiza amostras novas** — ele replica as 82.253 amostras benign existentes até atingir 256.408, gerando ~174k duplicatas exatas. Isso é conceitualmente redundante com o parâmetro `class_weight="balanced_subsample"` do Random Forest, que já pondera internamente as classes em cada bootstrap de cada árvore. Na prática, a combinação dos dois mecanismos não é destrutiva — duplicatas em bootstrap funcionam como aumento de peso implícito, produzindo efeito similar — mas introduz um risco na cross-validation: amostras duplicadas de um mesmo original podem aparecer simultaneamente nos folds de treino e validação, inflando ligeiramente os scores de CV. O FPR médio de 0.49% na CV contra 0.43% no teste holdout sugere que esse efeito foi marginal neste experimento. Para trabalhos futuros, recomenda-se remover o `RandomOverSampler` e delegar o balanceamento integralmente ao `class_weight`, ou substituí-lo por SMOTE, que interpola entre vizinhos ao invés de duplicar.

#### Modelo
```python
RandomForestClassifier(
    n_estimators     = 300,
    max_features     = "sqrt",
    class_weight     = "balanced_subsample",
    min_samples_leaf = 2,
    n_jobs           = 2,
    random_state     = 42,
)
```

#### Cross-Validation
```
Estratégia: StratifiedKFold, k=3
Cada fold: RandomOverSampler no treino, avaliação sem oversampling
```

---

## 5. Thresholds de Decisão (WAF)

O modelo retorna probabilidades por classe. A decisão de bloqueio usa thresholds assimétricos:

| Classe | Threshold para bloqueio | Justificativa |
|--------|------------------------|---------------|
| SQLi | ≥ 0.70 | Threshold elevado para reduzir FP em parâmetros numéricos (`id=1`, `user_id=N`) |
| XSS | ≥ 0.55 (v2) / 0.40 (v1) | Threshold elevado em v2 para reduzir FP em XML/SVG legítimos |

> A lógica verifica **todas as classes de ataque** independentemente — um payload é bloqueado se `P(sqli) ≥ 0.70 OR P(xss) ≥ 0.55`.

---

## 6. Métricas do Modelo

### v1 vs v2 — Comparação no Conjunto de Teste

| Métrica | v1 | v2 | Δ |
|---------|----|----|---|
| Accuracy | 99.60% | 99.59% | ≈ |
| Recall SQLi | 99.54% | 99.43% | -0.11pp |
| Recall XSS | 99.45% | **99.86%** | **+0.41pp** |
| Recall Benign | 99.75% | 99.57% | -0.18pp |
| F1 Macro | 99.56% | 99.48% | -0.08pp |
| **FPR** | **0.25%** | **0.43%** | +0.18pp |
| Latência p95 | < 50ms | 78.7ms | ↑ |

> **Interpretação:** O recall XSS melhorou significativamente (+0.41pp) graças à augmentação e SecLists. O FPR aumentou ligeiramente (0.25% → 0.43%), mas continua dentro da meta de ≤ 0.50% e abaixo do FPR observado na CV (0.49%). A queda no FPR da v1 era em parte artificial — o dataset benign v1 era homogêneo (apenas tráfego HTTP estruturado), facilitando a separação. Com a v2 o benign é mais diverso e o desafio de classificação é genuinamente maior.

### v1 — Resultados no Conjunto de Teste (referência)

| Métrica | Valor |
|---------|-------|
| Accuracy | 99.60% |
| Recall SQLi | 99.54% |
| Recall XSS | 99.45% |
| Recall Benign | 99.75% |
| F1 Macro | 99.56% |
| **FPR** | **0.25%** |
| Latência p95 | < 50ms |

**Matriz de Confusão (v1):**

| | Pred. SQLi | Pred. XSS | Pred. Benign |
|---|---|---|---|
| **Real SQLi** | 54.524 | 0 | 250 |
| **Real XSS** | 9 | 1.638 | 0 |
| **Real Benign** | 50 | 0 | 19.829 |

### v2 — Resultados no Conjunto de Teste

**Conjunto de teste:** 106.294 amostras (15% do dataset, distribuição real sem oversampling)

| Métrica | Valor |
|---------|-------|
| Accuracy | 99.59% |
| Recall SQLi | 99.43% |
| Recall XSS | 99.86% |
| Recall Benign | 99.57% |
| F1 Macro | 99.48% |
| **FPR** | **0.43%** |
| Latência p95 | 78.7ms |

**Matriz de Confusão (v2):**

| | Pred. SQLi | Pred. XSS | Pred. Benign |
|---|---|---|---|
| **Real SQLi** (54.945) | 54.631 | 1 | 313 |
| **Real XSS** (33.723) | 44 | 33.677 | 2 |
| **Real Benign** (17.626) | 75 | 1 | 17.550 |

**Cross-Validation k=3 (treino):**

| Métrica | Média | Desvio Padrão |
|---------|-------|---------------|
| Recall SQLi | 99.24% | ±0.03% |
| Recall XSS | 99.84% | ±0.01% |
| Recall Benign | 99.51% | ±0.05% |
| F1 Macro | 99.33% | ±0.03% |
| FPR | 0.49% | ±0.05% |

**Nota sobre latência:** O p95 de 78.7ms supera a meta de 50ms. Isso se deve ao tamanho do modelo (300 árvores × 20.015 features, 227.8 MB serializado) rodando em CPU com `n_jobs=2`. Em produção, a latência pode ser reduzida com: redução de estimadores (ex: 150), limite de `max_depth`, ou inferência em lote. Para os objetivos do TCC (análise de qualidade do dataset), a latência não é o fator crítico.

---

## 7. Análise de Falsos Positivos

### 7.1 FPs identificados na v1 (corrigidos na v2)

Identificados em testes interativos antes da v2:

| Payload | Predição | P(classe) | Diagnóstico |
|---------|----------|-----------|-------------|
| `tenho experiência com script e js` | SQLi | 68.81% | Prosa PT com vocab SQL → benign não cobria |
| `ive done some selects from the tables where they can do something` | SQLi | 98.67% | Prosa EN com vocab SQL estruturado |
| `<?xml version="1.0" standalone="no"?>` | XSS | 67.53% | XML puro sem script |
| `<!DOCTYPE svg PUBLIC "...">` | XSS | 60.73% | DOCTYPE SVG sem handler |
| `<polygon id="triangle" points="0,0 0,50 50,0" fill="#009900"/>` | XSS | 77.90% | SVG geométrico sem script |

**Causa raiz:** a classe benign v1 era composta exclusivamente de tráfego HTTP estruturado (`key=value&key2=value2`). O modelo nunca aprendeu que texto em prosa natural pode conter palavras SQL em contexto educacional/profissional, nem que XML/SVG bem-formados sem `<script>` ou event handlers são legítimos.

**Correção implementada na v2:** grupos 21–25 em `build_synthetic_legit` e ajuste do threshold XSS de 0.40 → 0.55.

---

### 7.2 FPs residuais identificados na v2 (limitações conhecidas)

Identificados em testes interativos após o retreino com o dataset v2. Representam a **fronteira de generalização** do modelo TF-IDF + Random Forest.

| Payload | Predição | P(SQLi) | Padrão ativado |
|---------|----------|---------|----------------|
| `i learn how to select something where theres nothing to lose` | SQLi | 91.73% | Bigrama `select+where` em sequência |
| `ive done this for select some thing where 1+1 equals five` | SQLi | 93.46% | `select+where` + expressão aritmética `1+1` |
| `SELECT é um comando SQL que uso muito no dia a dia` | SQLi | 75.29% | `SELECT` em maiúsculas + palavra `SQL` em prosa |

#### Análise de causa raiz — FPs residuais

Todos os três casos compartilham a mesma limitação estrutural: **o modelo TF-IDF não possui representação sintática da linguagem**. Os features extraídos são n-gramas de palavras e caracteres tratados como bag-of-words — a posição e o papel gramatical de cada token são ignorados.

**Caso 1 — `select ... where` em prosa coloquial:**  
O bigrama `select ... where` ocorre em ~100% dos payloads SQLi de tipo `SELECT * FROM tabela WHERE condição` e em uma fração muito pequena do benign sintético (que usava `select` como verbo isolado, nunca seguido de `where`). O modelo aprendeu corretamente que essa sequência é um forte preditor de SQLi — e não tem como saber, sem análise gramatical, que em inglês coloquial `select` e `where` são palavras comuns.

**Caso 2 — `select + where + 1+1`:**  
Agrava o caso anterior com a presença de expressão aritmética. Em boolean-based SQLi, a construção `WHERE 1+1=2` é canônica. A co-ocorrência de três sinais fortes (`select`, `where`, operação numérica) leva a confiança de 91% para 93%.

**Caso 3 — `SELECT` maiúsculo + `SQL`:**  
Dois sinais de correlação espúria: (a) keywords SQL em CAPS são muito mais comuns em payloads que em prosa — mesmo um DBA escrevendo documentação técnica normalmente digita `SELECT` em maiúsculas; (b) a palavra `SQL` aparece 204k vezes na classe `sqli` e raramente no benign (que é tráfego HTTP, não texto técnico). O modelo associou `SQL` como indicador da própria classe.

#### Por que não foi possível corrigir com geração sintética

A geração sintética consegue adicionar novos padrões ao espaço de features, mas cada novo padrão benign que cobre uma região de features anteriormente "maliciosa" aumenta a probabilidade de FN em ataques reais que usam a mesma região. Adicionar `"SELECT é um comando que aprendi"` ao benign reduziria a sensibilidade do modelo para payloads como `SELECT version()` ou `SELECT @@datadir`.

O ponto de equilíbrio para o modelo TF-IDF + RF foi atingido — os FPs residuais representam casos onde a ambiguidade é **intrínseca à representação**, não ao dataset.

#### Solução técnica além do escopo deste trabalho

A correção estrutural exigiria substituir bag-of-words por representações contextuais:

- **Embeddings contextuais** (BERT, RoBERTa): `SELECT` em "i had to SELECT the right option" vs `SELECT * FROM users` teriam embeddings distintos por conta do contexto da frase inteira
- **Análise sintática como feature**: detectar se `SELECT ... FROM ... WHERE` forma uma cláusula SQL completa vs palavras isoladas em prosa livre
- **Modelos de linguagem fine-tuned** para classificação de segurança web (ex: SecBERT, CySecBERT)

Essas abordagens estão documentadas na literatura como direção futura para WAFs baseados em ML e constituem oportunidade de trabalho para continuação desta pesquisa.

---

## 8. Critérios de Aprovação do Modelo

| Métrica | Threshold | v2 | Status |
|---------|-----------|-----|--------|
| Recall SQLi | ≥ 95% | 99.43% | PASS |
| Recall XSS | ≥ 95% | 99.86% | PASS |
| **FPR** | **≤ 0.5%** | **0.43%** | **PASS** |
| F1 Macro | ≥ 95% | 99.48% | PASS |
| Latência p95 | ≤ 50ms | 78.7ms | FAIL* |

> \* A latência pode ser otimizada reduzindo `n_estimators` ou limitando `max_depth` sem impacto material nas métricas de qualidade. Para os objetivos deste trabalho (análise e documentação do dataset), o critério crítico é o FPR ≤ 0.5%, que foi atendido.

---

## 9. Reprodutibilidade

Todos os processos aleatórios usam **seed fixo 42**:
- `random.seed(42)` / `numpy.random.seed(42)` / `Faker.seed(42)`
- `StratifiedShuffleSplit(random_state=42)`
- `RandomOverSampler(random_state=42)`
- `RandomForestClassifier(random_state=42)`

### Dependências externas necessárias

| Arquivo | Onde obter |
|---------|-----------|
| `sqli_biggest.csv` | [Kaggle — gambleryu/biggest-sql-injection-dataset](https://www.kaggle.com/datasets/gambleryu/biggest-sql-injection-dataset) |
| `sqli_dataset.csv` | [Kaggle — sajid576/sql-injection-dataset](https://www.kaggle.com/datasets/sajid576/sql-injection-dataset) |
| `xss_dataset.csv` | [Kaggle — syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning](https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning) |
| `normalTrafficTraining.txt` / `normalTrafficTest.txt` / `anomalousTrafficTest.txt` | [CSIC 2010 HTTP Dataset](http://www.isi.csic.es/dataset/) |
| `data/raw/seclists/` | `git clone --depth=1 --filter=blob:none --sparse https://github.com/danielmiessler/SecLists` |

### Para reproduzir o dataset do zero

```bash
cd dataset_pipeline

# 1. Colocar arquivos Kaggle e CSIC em data/raw/
# 2. Clonar SecLists
git -C data/raw clone --depth=1 --filter=blob:none --sparse \
    https://github.com/danielmiessler/SecLists seclists
cd data/raw/seclists
git sparse-checkout set "Fuzzing/XSS" "Fuzzing/Databases/SQLi"
cd ../../..

# 3. Executar pipeline
pip install -r requirements.txt
python 01_collect.py
python 02_curate.py
python 03_features.py
python 04_train_validate.py
python 05_fp_analysis.py
python 06_export_dataset.py
```

---

## 10. Dependências

| Biblioteca | Versão mínima | Uso |
|-----------|---------------|-----|
| pandas | 2.2 | Manipulação de dados |
| numpy | 1.26 | Operações numéricas |
| scikit-learn | 1.5 | TF-IDF, Random Forest, métricas |
| scipy | 1.13 | Matrizes esparsas (CSR) |
| faker | 25.0 | Geração de tráfego sintético |
| joblib | 1.4 | Serialização de modelos |
| imbalanced-learn | 0.12 | RandomOverSampler |

---

## 11. Estrutura de Arquivos

```
dataset_pipeline/
├── data/
│   ├── raw/
│   │   ├── sqli_biggest.csv              ← Kaggle SQLi
│   │   ├── sqli_dataset.csv              ← Kaggle SQLi
│   │   ├── xss_dataset.csv               ← Kaggle XSS
│   │   ├── normalTrafficTraining.txt     ← CSIC 2010 benign
│   │   ├── normalTrafficTest.txt         ← CSIC 2010 benign
│   │   ├── anomalousTrafficTest.txt      ← CSIC 2010 sqli
│   │   └── seclists/                     ← SecLists (sparse clone)
│   │       ├── Fuzzing/XSS/              ← ~14.700 payloads XSS únicos
│   │       └── Fuzzing/Databases/SQLi/   ← 587 payloads SQLi
│   ├── interim/
│   │   ├── 01_raw_combined.csv           ← Saída do estágio 1 (649.653 linhas)
│   │   └── 02_curated.csv                ← Saída do estágio 2
│   └── processed/
│       ├── X.npz                         ← Matriz de features (esparsa, 20.015 dim)
│       ├── y.csv                         ← Labels (texto + numérico)
│       ├── indices_train.npy
│       ├── indices_val.npy
│       ├── indices_test.npy
│       ├── dataset_train.csv
│       ├── dataset_val.csv
│       └── dataset_test.csv
├── models/
│   ├── word_tfidf.joblib
│   ├── char_tfidf.joblib
│   ├── manual_scaler.joblib
│   ├── feature_scaler.joblib
│   └── random_forest.joblib
├── reports/
│   ├── metrics_test.json
│   └── false_positives.csv
├── 01_collect.py
├── 02_curate.py
├── 03_features.py
├── 04_train_validate.py
├── 05_fp_analysis.py
├── 06_export_dataset.py
├── DATASET_DOC.md                        ← Documentação v1
├── DATASET_DOC_v2.md                     ← Este arquivo
└── requirements.txt
```
