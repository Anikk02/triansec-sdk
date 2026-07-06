"""
Logging configuration for TrianSec SDK.

This module provides:
- Configurable logging with different levels
- Structured logging support
- Log filtering and formatting
- Debug mode logging
- Sensitive data redaction
"""

import logging
import sys
from typing import Optional, Dict, Any, Union
from logging.handlers import RotatingFileHandler
import json
from datetime import datetime

from triansec.constants import (
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL,
    LOG_FORMAT,
    LOG_DATE_FORMAT,
    ENV_LOG_LEVEL,
    ENV_LOG_FORMAT,
    ENV_DEBUG,
)


# ============================================================
# 📋 LOG LEVEL MAPPING
# ============================================================

LOG_LEVEL_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


# ============================================================
# 🔍 LOG FILTERS
# ============================================================

class SensitiveDataFilter(logging.Filter):
    """
    Filter to redact sensitive data from log messages.
    """
    
    def __init__(self, sensitive_keys: Optional[list] = None):
        super().__init__()
        self.sensitive_keys = sensitive_keys or [
            "api_key",
            "password",
            "token",
            "secret",
            "authorization",
            "cookie",
            "x-api-key",
            "bearer",
            "access_token",
            "refresh_token",
        ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """
        Redact sensitive data from log messages.
        
        Args:
            record: Log record to filter
            
        Returns:
            True if log should be kept
        """
        if hasattr(record, "msg") and isinstance(record.msg, str):
            for key in self.sensitive_keys:
                # Redact sensitive key-value pairs
                import re
                pattern = rf'({key}["\']?\s*[:=]\s*["\']?)([^"\',\s]+)(["\']?)'
                record.msg = re.sub(
                    pattern,
                    r'\1[REDACTED]\3',
                    record.msg,
                    flags=re.IGNORECASE
                )
                
                # Redact sensitive values in JSON-like structures
                pattern = rf'"({key})"\s*:\s*"[^"]*"'
                record.msg = re.sub(
                    pattern,
                    rf'"{key}": "[REDACTED]"',
                    record.msg,
                    flags=re.IGNORECASE
                )
        
        return True


class MaxLengthFilter(logging.Filter):
    """
    Filter to truncate log messages to maximum length.
    """
    
    def __init__(self, max_length: int = 10000):
        super().__init__()
        self.max_length = max_length
    
    def filter(self, record: logging.LogRecord) -> bool:
        """
        Truncate log messages to maximum length.
        
        Args:
            record: Log record to filter
            
        Returns:
            True if log should be kept
        """
        if hasattr(record, "msg") and isinstance(record.msg, str):
            if len(record.msg) > self.max_length:
                record.msg = record.msg[:self.max_length] + "... (truncated)"
        return True


# ============================================================
# 🎨 LOG FORMATTERS
# ============================================================

class StructuredFormatter(logging.Formatter):
    """
    JSON structured log formatter for machine-readable logs.
    """
    
    def __init__(
        self,
        include_timestamp: bool = True,
        include_level: bool = True,
        include_name: bool = True,
        include_module: bool = True,
        include_function: bool = True,
        include_line: bool = True,
        include_process: bool = False,
        include_thread: bool = False,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.include_timestamp = include_timestamp
        self.include_level = include_level
        self.include_name = include_name
        self.include_module = include_module
        self.include_function = include_function
        self.include_line = include_line
        self.include_process = include_process
        self.include_thread = include_thread
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.
        
        Args:
            record: Log record to format
            
        Returns:
            JSON formatted log message
        """
        log_data = {}
        
        if self.include_timestamp:
            log_data["timestamp"] = datetime.utcnow().isoformat()
        
        if self.include_level:
            log_data["level"] = record.levelname
        
        if self.include_name:
            log_data["logger"] = record.name
        
        if self.include_module:
            log_data["module"] = record.module
        
        if self.include_function:
            log_data["function"] = record.funcName
        
        if self.include_line:
            log_data["line"] = record.lineno
        
        if self.include_process:
            log_data["process"] = record.process
            log_data["process_name"] = record.processName
        
        if self.include_thread:
            log_data["thread"] = record.thread
            log_data["thread_name"] = record.threadName
        
        # Add custom fields from extra
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            log_data.update(record.extra)
        
        # Add exception info
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add message
        log_data["message"] = record.getMessage()
        
        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """
    Colorized log formatter for terminal output.
    """
    
    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",      # Reset
        "BOLD": "\033[1m",       # Bold
    }
    
    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None):
        super().__init__(fmt=fmt, datefmt=datefmt)
        self.default_fmt = fmt or LOG_FORMAT
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with colors.
        
        Args:
            record: Log record to format
            
        Returns:
            Colorized log message
        """
        # Save original levelname
        original_levelname = record.levelname
        
        # Add color codes
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        record.levelname = f"{color}{record.levelname}{self.COLORS['RESET']}"
        
        # Add bold for critical
        if record.levelname == "CRITICAL":
            record.levelname = f"{self.COLORS['BOLD']}{record.levelname}{self.COLORS['RESET']}"
        
        # Format message
        result = super().format(record)
        
        # Restore original levelname
        record.levelname = original_levelname
        
        return result


# ============================================================
# ⚙️ LOGGER CONFIGURATION
# ============================================================

def configure_logging(
    level: Union[str, int] = LOG_LEVEL_INFO,
    format_type: str = "text",
    log_file: Optional[str] = None,
    max_file_size: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
    enable_console: bool = True,
    enable_structured: bool = False,
    enable_colors: bool = True,
    max_log_length: int = 10000,
    redact_sensitive: bool = True,
    loggers: Optional[Dict[str, Union[str, int]]] = None,
) -> None:
    """
    Configure logging for the SDK.
    
    Args:
        level: Log level (string or int)
        format_type: "text", "json", or "structured"
        log_file: Path to log file (optional)
        max_file_size: Maximum log file size in bytes
        backup_count: Number of backup files to keep
        enable_console: Enable console logging
        enable_structured: Use structured JSON logging
        enable_colors: Enable colored output
        max_log_length: Maximum log message length
        redact_sensitive: Redact sensitive data
        loggers: Dictionary of logger names and levels to override
    
    Examples:
        >>> configure_logging(level="DEBUG")
        >>> configure_logging(level="INFO", log_file="logs/sdk.log")
        >>> configure_logging(level="WARNING", enable_structured=True)
    """
    # Convert level
    if isinstance(level, str):
        level = LOG_LEVEL_MAP.get(level.lower(), logging.INFO)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter
    if enable_structured or format_type.lower() in ("json", "structured"):
        formatter = StructuredFormatter()
    elif enable_colors and sys.stdout.isatty():
        formatter = ColoredFormatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    else:
        formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    
    # Add console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        
        # Add filters
        if redact_sensitive:
            console_handler.addFilter(SensitiveDataFilter())
        if max_log_length:
            console_handler.addFilter(MaxLengthFilter(max_log_length))
        
        root_logger.addHandler(console_handler)
    
    # Add file handler
    if log_file:
        try:
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_file_size,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            
            # Add filters
            if redact_sensitive:
                file_handler.addFilter(SensitiveDataFilter())
            if max_log_length:
                file_handler.addFilter(MaxLengthFilter(max_log_length))
            
            root_logger.addHandler(file_handler)
        except Exception as e:
            # Fallback to console if file handler fails
            root_logger.warning(f"Failed to create log file handler: {e}")
    
    # Configure specific loggers
    if loggers:
        for logger_name, logger_level in loggers.items():
            if isinstance(logger_level, str):
                logger_level = LOG_LEVEL_MAP.get(logger_level.lower(), logging.INFO)
            logging.getLogger(logger_name).setLevel(logger_level)
    
    # Set default levels for third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(
    name: str,
    level: Optional[Union[str, int]] = None,
) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (usually __name__)
        level: Override log level for this logger
        
    Returns:
        Configured logger instance
    
    Examples:
        >>> logger = get_logger(__name__)
        >>> logger.info("Security middleware initialized")
        >>> logger.debug("Request processed", extra={"request_id": "123"})
    """
    logger = logging.getLogger(name)
    
    if level:
        if isinstance(level, str):
            level = LOG_LEVEL_MAP.get(level.lower(), logging.INFO)
        logger.setLevel(level)
    
    return logger


# ============================================================
# 🔧 LOGGER HELPER FUNCTIONS
# ============================================================

def log_with_context(
    logger: logging.Logger,
    level: int,
    message: str,
    **context: Any,
) -> None:
    """
    Log a message with additional context.
    
    Args:
        logger: Logger instance
        level: Log level
        message: Log message
        **context: Additional context to include
    
    Examples:
        >>> log_with_context(
        ...     logger,
        ...     logging.INFO,
        ...     "Request processed",
        ...     request_id="123",
        ...     action="allow",
        ...     latency=15.2
        ... )
    """
    extra = {"extra": context}
    logger.log(level, message, extra=extra)


def log_request(
    logger: logging.Logger,
    method: str,
    path: str,
    request_uuid: str,
    **context: Any,
) -> None:
    """
    Log an incoming request.
    
    Args:
        logger: Logger instance
        method: HTTP method
        path: Request path
        request_uuid: Request UUID
        **context: Additional context
    
    Examples:
        >>> log_request(
        ...     logger,
        ...     "GET",
        ...     "/api/users",
        ...     "123e4567-e89b-12d3-a456-426614174000",
        ...     client_ip="192.168.1.1"
        ... )
    """
    log_with_context(
        logger,
        logging.INFO,
        f"Request: {method} {path}",
        method=method,
        path=path,
        request_uuid=request_uuid,
        **context,
    )


def log_decision(
    logger: logging.Logger,
    action: str,
    request_uuid: str,
    path: str,
    method: str,
    **context: Any,
) -> None:
    """
    Log a security decision.
    
    Args:
        logger: Logger instance
        action: Security action (allow/block/throttle)
        request_uuid: Request UUID
        path: Request path
        method: HTTP method
        **context: Additional context
    
    Examples:
        >>> log_decision(
        ...     logger,
        ...     "block",
        ...     "123e4567-e89b-12d3-a456-426614174000",
        ...     "/api/login",
        ...     "POST",
        ...     risk_score=0.85,
        ...     reason="Multiple failed attempts"
        ... )
    """
    log_level = logging.INFO if action == "allow" else logging.WARNING
    
    log_with_context(
        logger,
        log_level,
        f"Decision: {action} - {method} {path}",
        action=action,
        method=method,
        path=path,
        request_uuid=request_uuid,
        **context,
    )


def log_block(
    logger: logging.Logger,
    request_uuid: str,
    path: str,
    method: str,
    reason: str,
    **context: Any,
) -> None:
    """
    Log a block decision.
    
    Args:
        logger: Logger instance
        request_uuid: Request UUID
        path: Request path
        method: HTTP method
        reason: Block reason
        **context: Additional context
    
    Examples:
        >>> log_block(
        ...     logger,
        ...     "123e4567-e89b-12d3-a456-426614174000",
        ...     "/api/login",
        ...     "POST",
        ...     "High request burst",
        ...     risk_score=0.92
        ... )
    """
    log_with_context(
        logger,
        logging.WARNING,
        f"BLOCK: {method} {path} - {reason}",
        action="block",
        method=method,
        path=path,
        request_uuid=request_uuid,
        reason=reason,
        **context,
    )


def log_throttle(
    logger: logging.Logger,
    request_uuid: str,
    path: str,
    method: str,
    reason: str,
    **context: Any,
) -> None:
    """
    Log a throttle decision.
    
    Args:
        logger: Logger instance
        request_uuid: Request UUID
        path: Request path
        method: HTTP method
        reason: Throttle reason
        **context: Additional context
    
    Examples:
        >>> log_throttle(
        ...     logger,
        ...     "123e4567-e89b-12d3-a456-426614174000",
        ...     "/api/login",
        ...     "POST",
        ...     "Suspicious activity detected",
        ...     risk_score=0.65
        ... )
    """
    log_with_context(
        logger,
        logging.WARNING,
        f"THROTTLE: {method} {path} - {reason}",
        action="throttle",
        method=method,
        path=path,
        request_uuid=request_uuid,
        reason=reason,
        **context,
    )


def log_error(
    logger: logging.Logger,
    error: Exception,
    request_uuid: str,
    context: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Log an error with context.
    
    Args:
        logger: Logger instance
        error: Exception instance
        request_uuid: Request UUID
        context: Additional context
    
    Examples:
        >>> log_error(
        ...     logger,
        ...     ConnectionError("Timeout"),
        ...     "123e4567-e89b-12d3-a456-426614174000",
        ...     {"engine_url": "https://api.triansec.com"}
        ... )
    """
    log_context = context or {}
    log_context["error_type"] = error.__class__.__name__
    log_context["error_message"] = str(error)
    log_context["request_uuid"] = request_uuid
    
    log_with_context(
        logger,
        logging.ERROR,
        f"Error: {error.__class__.__name__} - {str(error)}",
        **log_context,
    )


def log_performance(
    logger: logging.Logger,
    operation: str,
    duration_ms: float,
    request_uuid: Optional[str] = None,
    **context: Any,
) -> None:
    """
    Log performance metrics.
    
    Args:
        logger: Logger instance
        operation: Operation name
        duration_ms: Duration in milliseconds
        request_uuid: Request UUID (optional)
        **context: Additional context
    
    Examples:
        >>> log_performance(
        ...     logger,
        ...     "engine_request",
        ...     12.5,
        ...     "123e4567-e89b-12d3-a456-426614174000",
        ...     endpoint="/v1/analyze"
        ... )
    """
    log_context = {
        "operation": operation,
        "duration_ms": round(duration_ms, 2),
        **context,
    }
    if request_uuid:
        log_context["request_uuid"] = request_uuid
    
    # Use DEBUG level for performance logs (or INFO if over threshold)
    level = logging.DEBUG
    if duration_ms > 100:
        level = logging.WARNING
    elif duration_ms > 50:
        level = logging.INFO
    
    log_with_context(
        logger,
        level,
        f"Performance: {operation} - {duration_ms:.2f}ms",
        **log_context,
    )


# ============================================================
# 🔧 DEFAULT CONFIGURATION
# ============================================================

def setup_default_logging() -> None:
    """
    Set up default logging configuration.
    
    This reads from environment variables:
    - TRIANSEC_LOG_LEVEL: Log level (default: INFO)
    - TRIANSEC_LOG_FORMAT: "text" or "json" (default: text)
    - TRIANSEC_DEBUG: Enable debug mode (true/false)
    
    Examples:
        >>> setup_default_logging()
    """
    import os
    
    # Read from environment
    log_level = os.getenv(ENV_LOG_LEVEL, LOG_LEVEL_INFO)
    log_format = os.getenv(ENV_LOG_FORMAT, "text")
    debug = os.getenv(ENV_DEBUG, "false").lower() == "true"
    
    if debug:
        log_level = LOG_LEVEL_DEBUG
    
    configure_logging(
        level=log_level,
        format_type=log_format,
        enable_structured=log_format == "json",
        enable_colors=True,
    )


# ============================================================
# 📋 EXPORTS
# ============================================================

__all__ = [
    # Configuration
    "configure_logging",
    "setup_default_logging",
    "get_logger",
    
    # Filters
    "SensitiveDataFilter",
    "MaxLengthFilter",
    
    # Formatters
    "StructuredFormatter",
    "ColoredFormatter",
    
    # Helper functions
    "log_with_context",
    "log_request",
    "log_decision",
    "log_block",
    "log_throttle",
    "log_error",
    "log_performance",
    
    # Constants
    "LOG_LEVEL_MAP",
]