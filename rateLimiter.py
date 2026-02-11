
from collections import defaultdict, deque
from datetime import datetime, timedelta

class RateLimiter:
    """
    Implementa um mecanismo de controle de tráfego baseado no algoritmo de Janela Deslizante (Sliding Window Log).
    
    Esta classe é responsável por mitigar ataques de negação de serviço (DoS) e força bruta, 
    limitando a quantidade de requisições que uma combinação única de IP e User-Agent 
    pode realizar dentro de um intervalo de tempo específico.

    Atributos:
        limit (int): Número máximo de requisições permitidas dentro da janela.
        window (int): Tamanho da janela de tempo em segundos (ex: 60 para 1 minuto).
        requests_log (defaultdict): Estrutura de memória que armazena timestamps das 
                                    requisições usando uma fila (deque) para cada chave (IP, UA).
    """
    def __init__(self, limit=100, window=60):
        self.limit = limit
        self.window = window
        self.requests_log = defaultdict(lambda: deque())

    def is_rate_limited(self, ip: str, ua: str) -> bool:
        """
        Verifica se uma requisição excede o limite permitido, limpando registros obsoletos 
        antes da validação.

        O método remove timestamps que já saíram da janela de tempo atual (popleft), 
        garantindo que o consumo de memória seja otimizado e que apenas requisições 
        dentro do intervalo configurado sejam contabilizadas.

        Args:
            ip (str): Endereço IP de origem da requisição.
            ua (str): Cabeçalho User-Agent do cliente para aumentar a precisão da identificação.

        Returns:
            bool: True se o limite foi atingido/excedido (bloquear), False caso contrário (permitir).
        """
        key = (ip, ua)
        now = datetime.now()
        window_start = now - timedelta(seconds=self.window)

        while self.requests_log[key] and self.requests_log[key][0] < window_start:
            self.requests_log[key].popleft()

        self.requests_log[key].append(now)
        return len(self.requests_log[key]) >= self.limit