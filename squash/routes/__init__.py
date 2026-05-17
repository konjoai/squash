"""squash.routes — modular FastAPI routers mounted onto squash.api.app.

This package keeps the legacy flat :mod:`squash.api` module intact while
new feature work lives in self-contained router modules:

* :mod:`squash.routes.compliance` — multi-framework clause scan and
  clause-similarity clustering.
* :mod:`squash.routes.trends` — risk-exposure trend persistence and
  ``GET /api/trends/risk`` endpoint.
"""
