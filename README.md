# TriAnSec SDK

[![PyPI version](https://badge.fury.io/py/triansec.svg)](https://badge.fury.io/py/triansec)
[![Python versions](https://img.shields.io/pypi/pyversions/triansec.svg)](https://pypi.org/project/triansec/)
[![License](https://img.shields.io/pypi/l/triansec.svg)](https://opensource.org/licenses/MIT)

**TriAnSec SDK** is a lightweight Python SDK for integrating the TrianSec API Security Platform into your FastAPI/Starlette applications. It provides behavior-driven API protection without modifying your existing business logic.

---

## ✨ Features

- 🔒 **Behavior-Driven Protection** - Analyzes request patterns, not just rate limits
- ⚡ **Fast Decision Path** - Sub-15ms latency for security decisions
- 🛡️ **Adaptive Policy Engine** - Dynamically applies ALLOW, BLOCK, or THROTTLE decisions
- 🧠 **Stateful Intelligence** - Maintains historical behavioral state per identity
- 📊 **Explainable Decisions** - Every decision includes a human-readable reason
- 🔌 **Plug-and-Play** - Minimal integration with just one line of code
- 🎯 **Multi-Tenant Isolation** - Each client's security posture is independent

---

## 📦 Installation

```bash
pip install triansec
```

For FastAPI support (optional):

```bash
pip install triansec[fastapi]
```

For development:

```bash
pip install triansec[dev]
```

---

## 🚀 Quick Start

### 1. Get Your API Key

Sign up at [TriAnSec](https://triansec.com) and generate your API key from the dashboard.

### 2. Add the Middleware

```python
from fastapi import FastAPI
from triansec import TriAnSec

app = FastAPI()

# Add security middleware
app.add_middleware(
    TriAnSec,
    api_key="ts_live_xxxxxxxxx",
    timeout=5,
    fallback_action="allow",
)

@app.get("/")
async def root():
    return {"message": "Protected by TrianSec"}
```

---

## 📋 Usage Examples

### Option 1: Direct Middleware (Simplest)

```python
from fastapi import FastAPI
from triansec import TriAnSec

app = FastAPI()

app.add_middleware(
    TriAnSec,
    api_key="ts_live_xxxxxxxxx",
    timeout=10,
    fallback_action="allow",
)
```

### Option 2: Class-based with Install

```python
from fastapi import FastAPI
from triansec.security import TriAnSec

app = FastAPI()

security = TriAnSec(
    api_key="ts_live_xxxxxxxxx",
    timeout=10,
    fallback_action="allow",
)

security.install(app)
```

### Option 3: One-Line Setup

```python
from fastapi import FastAPI
from triansec.security import setup_security

app = FastAPI()

security = setup_security(
    app,
    api_key="ts_live_xxxxxxxxx",
    timeout=10,
    fallback_action="allow",
    add_health=True,
    add_shutdown=True,
)
```

### With Configuration Object

```python
from fastapi import FastAPI
from triansec import TriAnSec, SecurityConfig

app = FastAPI()

config = SecurityConfig(
    api_key="ts_live_xxxxxxxxx",
    timeout=10,
    fallback_action="block",
    enable_cache=True,
    cache_ttl=600,
)

app.add_middleware(TriAnSec, config=config)
```

---

## ⚙️ Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | `str` | **Required** | Your TrianSec API key |
| `engine_url` | `str` | Hardcoded | Security engine URL (you don't need to set this) |
| `timeout` | `int` | `5` | Request timeout in seconds |
| `retry_count` | `int` | `3` | Number of retry attempts |
| `fallback_action` | `str` | `"allow"` | Action when engine is unreachable (`"allow"` or `"block"`) |
| `enable_cache` | `bool` | `True` | Enable local decision caching |
| `cache_ttl` | `int` | `300` | Cache TTL in seconds |
| `cache_maxsize` | `int` | `1000` | Maximum cache entries |
| `enable_debug` | `bool` | `False` | Enable debug mode |
| `bypass_paths` | `List[str]` | Control plane paths | Paths to bypass security |

---

## 🔧 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TRIANSEC_API_KEY` | Your TrianSec API key | (Required) |
| `TRIANSEC_ENGINE_URL` | Security engine URL | `https://api.triansec.com` |
| `TRIANSEC_TIMEOUT` | Request timeout in seconds | `5` |
| `TRIANSEC_RETRY_COUNT` | Number of retry attempts | `3` |
| `TRIANSEC_FALLBACK_ACTION` | Fallback action (`allow` or `block`) | `allow` |
| `TRIANSEC_CACHE_ENABLED` | Enable cache (`true` or `false`) | `true` |
| `TRIANSEC_CACHE_TTL` | Cache TTL in seconds | `300` |
| `TRIANSEC_DEBUG` | Debug mode (`true` or `false`) | `false` |

---

## 🔒 How It Works

```
Incoming Request
       │
       ▼
  SDK Middleware
       │
       ▼
Extract Request Data (IP, User-Agent, Headers, etc.)
       │
       ▼
Check Local Cache
       │
       ▼
Send to Security Engine (with API key from request)
       │
       ▼
Security Engine validates API key, analyzes behavior
       │
       ▼
Return Decision (ALLOW / BLOCK / THROTTLE)
       │
       ▼
Apply Decision
       │
       ▼
Your Application Logic
```

---

## 🛡️ Security Decisions

| Decision | Description |
|----------|-------------|
| **ALLOW** | Request is legitimate, pass through to your application |
| **THROTTLE** | Request is suspicious, pass through with throttle headers |
| **BLOCK** | Request is malicious, return `429 Too Many Requests` |

---

## 🧪 Development

### Setup

```bash
git clone https://github.com/triansec/triansec-sdk.git
cd triansec-sdk
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .[dev]
```

### Run Tests

```bash
pytest
```

### Run Tests with Coverage

```bash
pytest --cov=triansec --cov-report=html
```

### Linting

```bash
ruff check .
black .
mypy triansec
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📞 Support

- Documentation: [https://docs.triansec.com](https://docs.triansec.com)
- Issues: [https://github.com/Anikk02/triansec-sdk/issues](https://github.com/triansec/triansec-sdk/issues)
- Email: support@triansec.com

---

## 👥 Authors

- **Aniket Paswan** - *Backend Architecture, System Design, Policy Engine, Security Middleware, Frontend Development*
- **Anjali Jha** - *Authentication Architecture, API Key Generation & Management, Frontend Development, UI/UX*
- **Anshika Pratap Singh** - *System Management, Frontend Development, UI/UX, Developer Dashboard*

---

## 🙏 Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/) and [Starlette](https://www.starlette.io/)
- Powered by [httpx](https://www.python-httpx.org/) and [Pydantic](https://docs.pydantic.dev/)