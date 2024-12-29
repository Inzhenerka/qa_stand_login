from typing import Any
import json
import boto3.session
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig


class SecretsManager:
    _cache: SecretCache

    def __init__(self, region_name: str = 'eu-west-1'):
        client = boto3.session.Session(region_name=region_name).client('secretsmanager')
        cache_config = SecretCacheConfig()
        self._cache = SecretCache(config=cache_config, client=client)

    def get_secret_value(self, secret_id: str) -> Any:
        value_str: str = self._cache.get_secret_string(secret_id)
        value: Any = json.loads(value_str)
        return value
