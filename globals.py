import os
from diskcache import Cache

cache_path = '/dev/shm/waf_cache' if os.path.exists('/dev/shm') else './waf_cache_temp'
waf_cache = Cache(cache_path)