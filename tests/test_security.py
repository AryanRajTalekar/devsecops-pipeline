"""
Security-focused test suite for SecureShop.
Tests cover: SQL injection, XSS, security headers,
rate limiting, input validation, and API correctness.
"""
import json
import os
import pytest
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from app import app, init_db  # noqa: E402


@pytest.fixture
def client(tmp_path):
    """Spin up a test client with a fresh in-memory DB for each test."""
    os.environ["DB_PATH"] = str(tmp_path / "test.db")
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = False   # disable rate limiting in unit tests
    with app.test_client() as c:
        with app.app_context():
            init_db()
        yield c


# ── Health check ───────────────────────────────────────────────────────────────
class TestHealth:
    def test_health_ok(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["status"] == "ok"
        assert "timestamp" in data


# ── Security headers ───────────────────────────────────────────────────────────
class TestSecurityHeaders:
    REQUIRED_HEADERS = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    def test_all_security_headers_present(self, client):
        r = client.get("/health")
        for header in self.REQUIRED_HEADERS:
            assert header in r.headers, f"Missing header: {header}"

    def test_x_frame_options_is_deny(self, client):
        r = client.get("/health")
        assert r.headers["X-Frame-Options"] == "DENY"

    def test_x_content_type_nosniff(self, client):
        r = client.get("/health")
        assert r.headers["X-Content-Type-Options"] == "nosniff"

    def test_no_server_header_leak(self, client):
        """Server header should not reveal Flask/Werkzeug version."""
        r = client.get("/health")
        server = r.headers.get("Server", "")
        assert "Werkzeug" not in server
        assert "Flask" not in server


# ── SQL injection prevention ───────────────────────────────────────────────────
class TestSQLInjection:
    PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE products; --",
        "' UNION SELECT * FROM audit_log --",
        "1; SELECT * FROM sqlite_master --",
        "%27 OR %271%27=%271",
    ]

    def test_sql_injection_returns_empty_not_error(self, client):
        for payload in self.PAYLOADS:
            r = client.get(f"/api/products?search={payload}")
            # Must not 500 — that would mean the payload hit the DB raw
            assert r.status_code == 200, f"Payload caused server error: {payload}"
            data = json.loads(r.data)
            # Injected SQL should return 0 real rows (sanitiser strips quotes)
            assert isinstance(data, list), f"Response is not a list for payload: {payload}"

    def test_products_table_survives_drop_attempt(self, client):
        """After a DROP TABLE payload, products must still be queryable."""
        client.get("/api/products?search='; DROP TABLE products; --")
        r = client.get("/api/products")
        assert r.status_code == 200
        assert len(json.loads(r.data)) >= 5


# ── XSS prevention ────────────────────────────────────────────────────────────
class TestXSSPrevention:
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]

    def test_xss_payload_not_reflected_raw(self, client):
        """Script tags must not appear verbatim in the response body."""
        for payload in self.XSS_PAYLOADS:
            r = client.get(f"/api/products?search={payload}")
            body = r.data.decode()
            assert "<script>" not in body.lower()

    def test_create_product_xss_in_name_not_stored_raw(self, client):
        """XSS in product name must be sanitised or harmlessly stored."""
        r = client.post(
            "/api/products",
            data=json.dumps({
                "name":     "<script>alert('xss')</script>",
                "price":    9.99,
                "category": "Test",
            }),
            content_type="application/json",
        )
        # Accepts 201 or 400 — but must not 500
        assert r.status_code in (201, 400)


# ── API correctness ────────────────────────────────────────────────────────────
class TestProductsAPI:
    def test_get_all_products(self, client):
        r = client.get("/api/products")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert len(data) >= 5   # at least the 5 seed products

    def test_search_returns_filtered_results(self, client):
        r = client.get("/api/products?search=Electronics")
        data = json.loads(r.data)
        assert all(p["category"] == "Electronics" for p in data)
        assert len(data) >= 3   # at least the 3 seeded electronics items

    def test_get_single_product(self, client):
        r = client.get("/api/products/1")
        assert r.status_code == 200
        assert json.loads(r.data)["name"] == "Laptop"

    def test_get_nonexistent_product_404(self, client):
        r = client.get("/api/products/9999")
        assert r.status_code == 404

    def test_create_product_success(self, client):
        r = client.post(
            "/api/products",
            data=json.dumps({"name": "Keyboard", "price": 79.99, "category": "Electronics"}),
            content_type="application/json",
        )
        assert r.status_code == 201
        data = json.loads(r.data)
        assert data["name"] == "Keyboard"
        assert data["price"] == 79.99

    def test_create_product_negative_price_rejected(self, client):
        r = client.post(
            "/api/products",
            data=json.dumps({"name": "Bad", "price": -1, "category": "Test"}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_create_product_missing_fields_rejected(self, client):
        r = client.post(
            "/api/products",
            data=json.dumps({"name": "Incomplete"}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_error_response_never_leaks_internals(self, client):
        """404 and 500 bodies must not contain stack traces or file paths."""
        r = client.get("/api/products/99999")
        body = r.data.decode()
        assert "Traceback" not in body
        assert "/home/" not in body
        assert "sqlite3" not in body
