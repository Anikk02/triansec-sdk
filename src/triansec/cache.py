"""
Local caching for TrianSec SDK.

This module provides a local in-memory cache for security decisions.
Caching reduces latency by serving cached decisions for repeated requests
from the same identity to the same endpoint.

The cache uses TTL (Time-To-Live) to automatically expire old entries.
Cache is thread-safe and supports async operations.

Cache Key Format:
    triansec:decision:{fingerprint}:{method}:{endpoint}

Usage:
    from triansec.cache import SecurityCache

    cache = SecurityCache(ttl=300, maxsize=1000)
    
    # Store decision
    cache.set(cache_key, decision)
    
    # Get decision
    decision = cache.get(cache_key)
    
    # Invalidate
    cache.invalidate(cache_key)
"""

import hashlib
import logging
import time
from typing import Optional, Any, Dict, Union, List
from threading import Lock
from collections import OrderedDict

from triansec.constants import (
    DEFAULT_CACHE_TTL,
    DEFAULT_CACHE_MAXSIZE,
    CACHE_KEY_PREFIX_DECISION,
)
from triansec.exceptions import CacheError
from triansec.logger import get_logger
from triansec.models.response import SecurityDecision

logger = get_logger(__name__)


class CacheEntry:
    """
    Cache entry with TTL support.
    
    Attributes:
        value: Cached value
        expires_at: Timestamp when the entry expires (Unix time in seconds)
        created_at: Timestamp when the entry was created
    """
    
    __slots__ = ("value", "expires_at", "created_at")
    
    def __init__(self, value: Any, ttl: int):
        """
        Initialize cache entry.
        
        Args:
            value: Value to cache
            ttl: Time-to-live in seconds
        """
        self.value = value
        self.expires_at = time.time() + ttl
        self.created_at = time.time()
    
    def is_expired(self) -> bool:
        """
        Check if the cache entry has expired.
        
        Returns:
            True if the entry has expired, False otherwise
        """
        return time.time() > self.expires_at
    
    @property
    def age(self) -> float:
        """
        Get the age of the entry in seconds.
        
        Returns:
            Age in seconds
        """
        return time.time() - self.created_at
    
    @property
    def ttl_remaining(self) -> float:
        """
        Get the remaining TTL in seconds.
        
        Returns:
            Remaining TTL in seconds (negative if expired)
        """
        return self.expires_at - time.time()


class LRUCache:
    """
    Thread-safe LRU (Least Recently Used) cache implementation.
    
    Uses OrderedDict to maintain access order. When the cache reaches
    maxsize, the least recently used item is evicted.
    """
    
    def __init__(self, maxsize: int = DEFAULT_CACHE_MAXSIZE):
        """
        Initialize LRU cache.
        
        Args:
            maxsize: Maximum number of entries in the cache
        """
        self.maxsize = maxsize
        self._cache: OrderedDict = OrderedDict()
        self._lock = Lock()
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
        
        Returns:
            Cached value or None if not found
        """
        with self._lock:
            if key in self._cache:
                # Move to end (most recently used)
                self._cache.move_to_end(key)
                entry = self._cache[key]
                if not entry.is_expired():
                    return entry.value
                else:
                    # Remove expired entry
                    del self._cache[key]
            return None
    
    def set(self, key: str, value: Any, ttl: int) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds
        """
        with self._lock:
            # If key exists, update it
            if key in self._cache:
                self._cache.move_to_end(key)
                self._cache[key] = CacheEntry(value, ttl)
            else:
                # Check if we need to evict
                if len(self._cache) >= self.maxsize:
                    # Evict least recently used (first item)
                    self._cache.popitem(last=False)
                self._cache[key] = CacheEntry(value, ttl)
    
    def delete(self, key: str) -> bool:
        """
        Delete key from cache.
        
        Args:
            key: Cache key
        
        Returns:
            True if key was deleted, False if not found
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def clear(self) -> None:
        """Clear all entries from cache."""
        with self._lock:
            self._cache.clear()
    
    def contains(self, key: str) -> bool:
        """
        Check if key exists in cache and is not expired.
        
        Args:
            key: Cache key
        
        Returns:
            True if key exists and is not expired
        """
        with self._lock:
            if key not in self._cache:
                return False
            if self._cache[key].is_expired():
                del self._cache[key]
                return False
            return True
    
    def get_size(self) -> int:
        """
        Get current cache size.
        
        Returns:
            Number of entries in cache
        """
        with self._lock:
            return len(self._cache)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        with self._lock:
            total_entries = len(self._cache)
            expired_count = 0
            total_age = 0.0
            
            for entry in self._cache.values():
                if entry.is_expired():
                    expired_count += 1
                total_age += entry.age
            
            avg_age = total_age / total_entries if total_entries > 0 else 0.0
            
            return {
                "size": total_entries,
                "maxsize": self.maxsize,
                "expired_entries": expired_count,
                "active_entries": total_entries - expired_count,
                "avg_age_seconds": avg_age,
                "usage_percent": (total_entries / self.maxsize * 100) if self.maxsize > 0 else 0,
            }


class SecurityCache:
    """
    Security decision cache for TrianSec SDK.
    
    This cache stores security decisions locally to reduce latency
    for repeated requests from the same identity to the same endpoint.
    
    Cache key format: triansec:decision:{fingerprint}:{method}:{endpoint}
    
    Attributes:
        ttl: Time-to-live in seconds for cache entries
        maxsize: Maximum number of entries in cache
        enabled: Whether caching is enabled
    
    Usage:
        cache = SecurityCache(ttl=300, maxsize=1000)
        
        # Store decision
        cache.set("fingerprint", "POST", "/api/login", decision)
        
        # Get decision
        decision = cache.get("fingerprint", "POST", "/api/login")
        
        # Invalidate
        cache.invalidate("fingerprint", "POST", "/api/login")
    """
    
    def __init__(
        self,
        ttl: int = DEFAULT_CACHE_TTL,
        maxsize: int = DEFAULT_CACHE_MAXSIZE,
        enabled: bool = True,
    ):
        """
        Initialize security cache.
        
        Args:
            ttl: Time-to-live in seconds for cache entries (default: 300)
            maxsize: Maximum number of entries in cache (default: 1000)
            enabled: Whether caching is enabled (default: True)
        """
        self.ttl = ttl
        self.maxsize = maxsize
        self.enabled = enabled
        
        self._cache = LRUCache(maxsize=maxsize)
        
        # Statistics
        self._hits = 0
        self._misses = 0
        self._sets = 0
        self._invalidates = 0
        
        if enabled:
            logger.info(
                f"SecurityCache initialized: "
                f"ttl={ttl}s, "
                f"maxsize={maxsize}, "
                f"enabled=True"
            )
        else:
            logger.info("SecurityCache initialized: disabled")
    
    # ============================================================
    # 🔑 CACHE KEY GENERATION
    # ============================================================
    
    @staticmethod
    def generate_key(
        fingerprint: str,
        method: str,
        endpoint: str,
        prefix: str = CACHE_KEY_PREFIX_DECISION,
    ) -> str:
        """
        Generate cache key from request parameters.
        
        Args:
            fingerprint: Identity fingerprint
            method: HTTP method (GET, POST, etc.)
            endpoint: Request endpoint
            prefix: Cache key prefix
        
        Returns:
            Cache key string
        
        Examples:
            >>> key = SecurityCache.generate_key(
            ...     "a1b2c3d4e5f6",
            ...     "POST",
            ...     "/api/login"
            ... )
            >>> key
            'triansec:decision:a1b2c3d4e5f6:POST:/api/login'
        """
        # Clean up endpoint
        endpoint = endpoint.rstrip("/") or "/"
        
        # Generate key
        key = f"{prefix}{fingerprint}:{method}:{endpoint}"
        
        # Hash if key is too long (SHA256 for consistent length)
        if len(key) > 200:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            key = f"{prefix}{key_hash}"
        
        return key
    
    @staticmethod
    def generate_key_from_data(request_data: Dict[str, Any]) -> str:
        """
        Generate cache key from request data dictionary.
        
        Args:
            request_data: Request data dictionary containing fingerprint, method, endpoint
        
        Returns:
            Cache key string
        
        Examples:
            >>> key = SecurityCache.generate_key_from_data({
            ...     "fingerprint": "a1b2c3d4e5f6",
            ...     "method": "POST",
            ...     "endpoint": "/api/login"
            ... })
        """
        fingerprint = request_data.get("fingerprint", "")
        method = request_data.get("method", "GET")
        endpoint = request_data.get("endpoint", "/")
        
        return SecurityCache.generate_key(fingerprint, method, endpoint)
    
    # ============================================================
    # 🔄 CACHE OPERATIONS
    # ============================================================
    
    def get(
        self,
        fingerprint: str,
        method: str,
        endpoint: str,
    ) -> Optional[SecurityDecision]:
        """
        Get cached decision.
        
        Args:
            fingerprint: Identity fingerprint
            method: HTTP method
            endpoint: Request endpoint
        
        Returns:
            Cached SecurityDecision or None if not found/expired
        
        Examples:
            >>> decision = cache.get("a1b2c3d4e5f6", "POST", "/api/login")
            >>> if decision:
            ...     print(f"Decision: {decision.action}")
        """
        if not self.enabled:
            return None
        
        key = self.generate_key(fingerprint, method, endpoint)
        entry = self._cache.get(key)
        
        if entry is not None:
            self._hits += 1
            logger.debug(f"Cache HIT: {key}")
            return entry
        else:
            self._misses += 1
            logger.debug(f"Cache MISS: {key}")
            return None
    
    def get_from_data(self, request_data: Dict[str, Any]) -> Optional[SecurityDecision]:
        """
        Get cached decision from request data dictionary.
        
        Args:
            request_data: Request data dictionary
        
        Returns:
            Cached SecurityDecision or None if not found/expired
        
        Examples:
            >>> decision = cache.get_from_data({
            ...     "fingerprint": "a1b2c3d4e5f6",
            ...     "method": "POST",
            ...     "endpoint": "/api/login"
            ... })
        """
        if not self.enabled:
            return None
        
        fingerprint = request_data.get("fingerprint", "")
        method = request_data.get("method", "GET")
        endpoint = request_data.get("endpoint", "/")
        
        return self.get(fingerprint, method, endpoint)
    
    def set(
        self,
        fingerprint: str,
        method: str,
        endpoint: str,
        decision: SecurityDecision,
        ttl: Optional[int] = None,
    ) -> None:
        """
        Store decision in cache.
        
        Args:
            fingerprint: Identity fingerprint
            method: HTTP method
            endpoint: Request endpoint
            decision: SecurityDecision to cache
            ttl: Optional TTL override (defaults to instance TTL)
        
        Examples:
            >>> cache.set("a1b2c3d4e5f6", "POST", "/api/login", decision)
        """
        if not self.enabled:
            return
        
        ttl = ttl or self.ttl
        key = self.generate_key(fingerprint, method, endpoint)
        
        self._cache.set(key, decision, ttl)
        self._sets += 1
        
        logger.debug(f"Cache SET: {key} (ttl={ttl}s)")
    
    def set_from_data(
        self,
        request_data: Dict[str, Any],
        decision: SecurityDecision,
        ttl: Optional[int] = None,
    ) -> None:
        """
        Store decision in cache from request data dictionary.
        
        Args:
            request_data: Request data dictionary
            decision: SecurityDecision to cache
            ttl: Optional TTL override (defaults to instance TTL)
        
        Examples:
            >>> cache.set_from_data(request_data, decision)
        """
        if not self.enabled:
            return
        
        fingerprint = request_data.get("fingerprint", "")
        method = request_data.get("method", "GET")
        endpoint = request_data.get("endpoint", "/")
        
        self.set(fingerprint, method, endpoint, decision, ttl)
    
    def invalidate(
        self,
        fingerprint: str,
        method: str,
        endpoint: str,
    ) -> bool:
        """
        Invalidate a cached decision.
        
        Args:
            fingerprint: Identity fingerprint
            method: HTTP method
            endpoint: Request endpoint
        
        Returns:
            True if key was invalidated, False if not found
        
        Examples:
            >>> cache.invalidate("a1b2c3d4e5f6", "POST", "/api/login")
            True
        """
        if not self.enabled:
            return False
        
        key = self.generate_key(fingerprint, method, endpoint)
        result = self._cache.delete(key)
        
        if result:
            self._invalidates += 1
            logger.debug(f"Cache INVALIDATE: {key}")
        else:
            logger.debug(f"Cache INVALIDATE FAILED: {key} (not found)")
        
        return result
    
    def invalidate_from_data(self, request_data: Dict[str, Any]) -> bool:
        """
        Invalidate cached decision from request data dictionary.
        
        Args:
            request_data: Request data dictionary
        
        Returns:
            True if key was invalidated, False if not found
        
        Examples:
            >>> cache.invalidate_from_data(request_data)
            True
        """
        if not self.enabled:
            return False
        
        fingerprint = request_data.get("fingerprint", "")
        method = request_data.get("method", "GET")
        endpoint = request_data.get("endpoint", "/")
        
        return self.invalidate(fingerprint, method, endpoint)
    
    def invalidate_by_prefix(self, prefix: str) -> int:
        """
        Invalidate all cache entries with a specific prefix.
        
        This is useful for invalidating all decisions for a specific identity.
        
        Args:
            prefix: Key prefix (e.g., "triansec:decision:{fingerprint}:")
        
        Returns:
            Number of entries invalidated
        
        Examples:
            >>> # Invalidate all decisions for a specific fingerprint
            >>> cache.invalidate_by_prefix("triansec:decision:a1b2c3d4e5f6:")
            3
        """
        if not self.enabled:
            return 0
        
        invalidated = 0
        # We need to iterate and find keys with the prefix
        # Since LRUCache uses OrderedDict, we can't efficiently filter
        # This is O(n) but cache size is limited
        keys_to_delete = []
        
        with self._cache._lock:
            for key in list(self._cache._cache.keys()):
                if key.startswith(prefix):
                    keys_to_delete.append(key)
            
            for key in keys_to_delete:
                del self._cache._cache[key]
                invalidated += 1
        
        self._invalidates += invalidated
        logger.debug(f"Cache INVALIDATE BY PREFIX: {prefix} ({invalidated} entries)")
        
        return invalidated
    
    # ============================================================
    # 🔍 CACHE INSPECTION
    # ============================================================
    
    def contains(
        self,
        fingerprint: str,
        method: str,
        endpoint: str,
    ) -> bool:
        """
        Check if a key exists in cache and is not expired.
        
        Args:
            fingerprint: Identity fingerprint
            method: HTTP method
            endpoint: Request endpoint
        
        Returns:
            True if key exists and is not expired
        
        Examples:
            >>> if cache.contains("a1b2c3d4e5f6", "POST", "/api/login"):
            ...     print("Decision is cached")
        """
        if not self.enabled:
            return False
        
        key = self.generate_key(fingerprint, method, endpoint)
        return self._cache.contains(key)
    
    def clear(self) -> None:
        """Clear all entries from cache."""
        if self.enabled:
            self._cache.clear()
            logger.debug("Cache CLEARED")
    
    # ============================================================
    # 📊 CACHE STATISTICS
    # ============================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        
        Examples:
            >>> stats = cache.get_stats()
            >>> stats["hits"]
            42
            >>> stats["hit_rate"]
            0.84
        """
        cache_stats = self._cache.get_stats()
        total_requests = self._hits + self._misses
        hit_rate = self._hits / total_requests if total_requests > 0 else 0.0
        
        return {
            "enabled": self.enabled,
            "ttl": self.ttl,
            "maxsize": self.maxsize,
            "size": cache_stats["size"],
            "active_entries": cache_stats["active_entries"],
            "expired_entries": cache_stats["expired_entries"],
            "usage_percent": cache_stats["usage_percent"],
            "avg_age_seconds": cache_stats["avg_age_seconds"],
            "hits": self._hits,
            "misses": self._misses,
            "sets": self._sets,
            "invalidates": self._invalidates,
            "total_requests": total_requests,
            "hit_rate": hit_rate,
        }
    
    def reset_stats(self) -> None:
        """Reset hit/miss statistics."""
        self._hits = 0
        self._misses = 0
        self._sets = 0
        self._invalidates = 0
        logger.debug("Cache stats reset")
    
    # ============================================================
    # 🔧 UTILITY METHODS
    # ============================================================
    
    def enable(self) -> None:
        """Enable caching."""
        self.enabled = True
        logger.info("Cache enabled")
    
    def disable(self) -> None:
        """Disable caching."""
        self.enabled = False
        logger.info("Cache disabled")
    
    def __repr__(self) -> str:
        """String representation of the cache."""
        stats = self.get_stats()
        return (
            f"SecurityCache("
            f"enabled={self.enabled}, "
            f"ttl={self.ttl}s, "
            f"size={stats['size']}/{self.maxsize}, "
            f"hit_rate={stats['hit_rate']:.2%}"
            f")"
        )


# ============================================================
# 🔧 GLOBAL CACHE INSTANCE
# ============================================================

# Global cache instance for the SDK
# This is the default cache used by the middleware
_global_cache: Optional[SecurityCache] = None


def get_global_cache() -> SecurityCache:
    """
    Get the global cache instance.
    
    If the global cache doesn't exist, it will be created with default settings.
    
    Returns:
        Global SecurityCache instance
    
    Examples:
        >>> cache = get_global_cache()
        >>> decision = cache.get(fingerprint, method, endpoint)
    """
    global _global_cache
    
    if _global_cache is None:
        _global_cache = SecurityCache()
    
    return _global_cache


def set_global_cache(cache: SecurityCache) -> None:
    """
    Set the global cache instance.
    
    Args:
        cache: SecurityCache instance to use as global cache
    
    Examples:
        >>> cache = SecurityCache(ttl=600, maxsize=2000)
        >>> set_global_cache(cache)
    """
    global _global_cache
    _global_cache = cache
    logger.info("Global cache instance updated")


def disable_global_cache() -> None:
    """Disable the global cache."""
    global _global_cache
    if _global_cache:
        _global_cache.disable()
    logger.info("Global cache disabled")


def enable_global_cache() -> None:
    """Enable the global cache."""
    global _global_cache
    if _global_cache:
        _global_cache.enable()
    else:
        _global_cache = SecurityCache()
    logger.info("Global cache enabled")


def clear_global_cache() -> None:
    """Clear the global cache."""
    global _global_cache
    if _global_cache:
        _global_cache.clear()
        logger.info("Global cache cleared")


# ============================================================
# 🔧 DEPRECATED COMPATIBILITY FUNCTIONS
# ============================================================

# These functions maintain compatibility with the original cache interface
# used in the middleware

def get_cached_decision(cache_key: str) -> Optional[SecurityDecision]:
    """
    Get cached decision by key (compatibility function).
    
    Args:
        cache_key: Full cache key
    
    Returns:
        Cached SecurityDecision or None
    """
    cache = get_global_cache()
    # Since we have the full key, we need to extract fingerprint, method, endpoint
    # This is inefficient but maintains compatibility
    # The middleware should use the new API directly
    try:
        parts = cache_key.split(":")
        if len(parts) >= 4:
            fingerprint = parts[2]
            method = parts[3]
            endpoint = ":".join(parts[4:]) if len(parts) > 4 else "/"
            return cache.get(fingerprint, method, endpoint)
    except Exception:
        return None
    
    return None


def cache_decision(cache_key: str, decision: SecurityDecision, ttl: int) -> None:
    """
    Cache decision by key (compatibility function).
    
    Args:
        cache_key: Full cache key
        decision: SecurityDecision to cache
        ttl: TTL in seconds
    """
    cache = get_global_cache()
    try:
        parts = cache_key.split(":")
        if len(parts) >= 4:
            fingerprint = parts[2]
            method = parts[3]
            endpoint = ":".join(parts[4:]) if len(parts) > 4 else "/"
            cache.set(fingerprint, method, endpoint, decision, ttl)
    except Exception:
        pass


def invalidate_cache(cache_key: str) -> bool:
    """
    Invalidate cached decision by key (compatibility function).
    
    Args:
        cache_key: Full cache key
    
    Returns:
        True if invalidated, False otherwise
    """
    cache = get_global_cache()
    try:
        parts = cache_key.split(":")
        if len(parts) >= 4:
            fingerprint = parts[2]
            method = parts[3]
            endpoint = ":".join(parts[4:]) if len(parts) > 4 else "/"
            return cache.invalidate(fingerprint, method, endpoint)
    except Exception:
        pass
    
    return False


def get_cache_stats() -> Dict[str, Any]:
    """
    Get global cache statistics (compatibility function).
    
    Returns:
        Dictionary with cache statistics
    """
    cache = get_global_cache()
    return cache.get_stats()


# ============================================================
# 📋 EXPORTS
# ============================================================

__all__ = [
    # Main classes
    "SecurityCache",
    "LRUCache",
    "CacheEntry",
    
    # Global cache functions
    "get_global_cache",
    "set_global_cache",
    "disable_global_cache",
    "enable_global_cache",
    "clear_global_cache",
    
    # Compatibility functions
    "get_cached_decision",
    "cache_decision",
    "invalidate_cache",
    "get_cache_stats",
]