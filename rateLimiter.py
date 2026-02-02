
from collections import defaultdict, deque
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self, limit=100, window=60):
        self.limit = limit
        self.window = window
        self.requests_log = defaultdict(lambda: deque())

    def is_rate_limited(self, ip, ua):
        key = (ip, ua)
        now = datetime.now()
        window_start = now - timedelta(seconds=self.window)

        while self.requests_log[key] and self.requests_log[key][0] < window_start:
            self.requests_log[key].popleft()

        self.requests_log[key].append(now)
        return len(self.requests_log[key]) >= self.limit