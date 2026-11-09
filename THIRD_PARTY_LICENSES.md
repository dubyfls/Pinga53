# Third-party licenses

Every dependency Pinga53 ships, and its license. All are permissive (MIT, BSD, Apache-2.0, ISC, PSF) except certifi (MPL-2.0, file-level copyleft; used unmodified). None is GPL or AGPL, so all are compatible with both the AGPL-3.0 release and Pinga53's commercial license.

Generated 2026-11-09. Regenerate after dependency changes.

## Engine (Go)

| Module | License |
| --- | --- |
| golang.org/x/net | BSD-3-Clause |
| golang.org/x/text | BSD-3-Clause |

Other golang.org/x modules in go.sum are build/test tooling, not compiled into the binary (BSD-3-Clause).

## Dashboard backend (Python, pinned in dashboard/backend/requirements.txt)

| Package | Version | License |
| --- | --- | --- |
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.16.0 | MIT |
| argon2-cffi | 25.1.0 | MIT |
| argon2-cffi-bindings | 26.1.0 | MIT |
| certifi | 2026.10.23 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| charset-normalizer | 3.5.2 | MIT |
| click | 8.5.1 | BSD-3-Clause |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| ecdsa | 0.19.2 | MIT |
| exceptiongroup | 1.3.1 | MIT License |
| fastapi | 0.162.2 | MIT |
| greenlet | 3.5.6 | MIT AND PSF-2.0 |
| h11 | 0.16.0 | MIT |
| httptools | 0.9.0 | MIT |
| idna | 3.20 | BSD-3-Clause |
| opentelemetry-api | 1.45.2 | Apache-2.0 |
| passlib | 1.7.4 | BSD |
| pyasn1 | 0.6.5 | BSD-2-Clause |
| pycparser | 3.11 | BSD-3-Clause |
| pydantic | 2.14.3 | MIT |
| pydantic_core | 2.50.4 | MIT |
| PyOTP | 2.10.0 | MIT |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| python-jose | 3.5.0 | MIT |
| PyYAML | 6.0.3 | MIT |
| requests | 2.34.2 | Apache-2.0 |
| rsa | 4.9.1 | Apache-2.0 |
| segno | 1.6.6 | BSD License |
| six | 1.17.0 | MIT |
| SQLAlchemy | 2.0.57 | MIT |
| starlette | 1.7.0 | BSD-3-Clause |
| typing_extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.5 | MIT |
| urllib3 | 2.8.0 | MIT |
| uvicorn | 0.54.0 | BSD-3-Clause |
| uvloop | 0.23.0 | MIT License |
| watchfiles | 1.3.0 | MIT |
| websockets | 16.1.1 | BSD-3-Clause |

## Dashboard frontend (npm, bundled into dashboard/frontend/dist)

| Package | License |
| --- | --- |
| js-tokens | MIT |
| loose-envify | MIT |
| lucide-react | ISC |
| react | MIT |
| react-dom | MIT |
| scheduler | MIT |
