from triansec import TriAnSec, SecurityConfig, get_version

print("✅ TrianSec SDK installed successfully!")
print(f"✅ Version: {TriAnSec.__module__}")

print(f"Package version: {get_version()}")

config = SecurityConfig(api_key="ts_live_test")
print(f"Config created: {config.is_configured()}")

print("✅ All imports working!")