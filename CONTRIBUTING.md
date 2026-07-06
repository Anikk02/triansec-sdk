# Contributing to TriAnSec SDK

First off, thank you for considering contributing to **TriAnSec SDK**! 🎉

We welcome contributions of all kinds and appreciate your help in making the SDK more secure, reliable, and developer-friendly.

You can contribute by:

- 🐛 Reporting bugs
- 💡 Suggesting new features or improvements
- 🛠️ Fixing bugs
- 📖 Improving documentation
- ✅ Writing tests
- 🤝 Becoming a maintainer

---

# Development Process

We use **GitHub** for:

- Source code hosting
- Issue tracking
- Feature requests
- Pull request reviews
- Release management

---

# Getting Started

## 1. Fork and Clone

```bash
git clone https://github.com/triansec/triansec-sdk.git
cd triansec-sdk
```

## 2. Create a Virtual Environment

### Linux / macOS

```bash
python -m venv venv
source venv/bin/activate
```

### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

## 3. Install Dependencies

```bash
pip install -e .[dev]
```

---

# Running Tests

Run the complete test suite:

```bash
pytest
```

Run a specific test:

```bash
pytest tests/test_middleware.py
```

Run with coverage:

```bash
pytest --cov=triansec --cov-report=html
```

Show missing coverage:

```bash
pytest --cov=triansec --cov-report=term-missing
```

---

# Code Quality

Before opening a pull request, ensure your code passes all quality checks.

## Format Code

```bash
black .
```

## Lint

```bash
ruff check .
```

## Type Checking

```bash
mypy triansec
```

---

# Pull Request Guidelines

Before submitting a pull request:

1. Fork the repository.
2. Create a feature branch from `main`.

```bash
git checkout -b feature/my-feature
```

3. Write clear, readable code.
4. Add or update tests when necessary.
5. Update documentation if APIs or behavior change.
6. Ensure all tests pass.
7. Run formatting, linting, and type checking.
8. Submit your Pull Request.

---

# Commit Message Convention

We follow the **Conventional Commits** specification.

Examples:

```text
feat: add API retry middleware
fix: resolve cache expiration bug
docs: update authentication guide
style: format source files
refactor: simplify client initialization
test: add middleware unit tests
chore: update development dependencies
```

---

# Reporting Bugs

When reporting a bug, please include:

- **Expected behavior**
- **Actual behavior**
- **Steps to reproduce**
- **Python version**
- **Operating System**
- **SDK version**
- **Error logs or traceback (if available)**

---

# Requesting Features

Feature requests are always welcome.

Please include:

- **Use case**
- **Problem being solved**
- **Proposed solution**
- **Possible alternatives**
- **Additional context (if any)**

---

# Project Structure

```text
triansec-sdk/
├── src/
│   └── triansec/
│       ├── __init__.py
│       ├── cache.py
│       ├── client.py
│       ├── config.py
│       ├── constants.py
│       ├── exceptions.py
│       ├── logging.py
│       ├── middleware.py
│       ├── security.py
│       ├── utils.py
│       ├── identity/
│       │   ├── __init__.py
│       │   └── resolver.py
│       └── models/
│           ├── __init__.py
│           └── response.py
│
├── tests/
│   ├── __init__.py
│   ├── test_cache.py
│   ├── test_client.py
│   ├── test_config.py
│   ├── test_middleware.py
│   ├── test_resolver.py
│   └── test_utils.py
│
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
└── .gitignore
```

---

# Release Process

Project maintainers follow this release workflow:

1. Update the version in `pyproject.toml`.
2. Update `CHANGELOG.md`.
3. Merge the release pull request.
4. Create a GitHub Release.
5. GitHub Actions automatically publishes the package to **PyPI**.

---

# License

By contributing to **TriAnSec SDK**, you agree that your contributions will be licensed under the **MIT License**.

---

# Questions or Support

If you have questions or need help:

- Open a GitHub Issue
- Contact us at **support@triansec.com**

---

Thank you for helping make **TriAnSec SDK** better! 🚀