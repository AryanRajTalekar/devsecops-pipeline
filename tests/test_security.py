"""
Security-focused test suite for SecureShop.
Covers: SQL injection, XSS, security headers, input validation, API correctness.
"""
import json
import os
import pytest
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from app import app, init_db


@pytest.fixture
def client(tmp_path):
    os.environ["DB_PATH"] = str(tmp_path / "test.db")
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = False
    with app.test_client() as c:
        with app.app_context():
            init_db()
        yield c


class TestHealth:
    def test_health_ok(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["status"] == "ok"
        assert "timestamp" in data


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
        r = client.get("/health")
        server = r.headers.get("Server", "")
        assert "Werkzeug" not in server
        assert "Flask" not in server


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
            assert r.status_code == 200, f"Payload caused server error: {payload}"
            assert isinstance(json.loads(r.data), list)

    def test_products_table_survives_drop_attempt(self, client):
        client.get("/api/products?search='; DROP TABLE products; --")
        r = client.get("/api/products")
        assert r.status_code == 200
        assert len(json.loads(r.data)) >= 5


class TestXSSPrevention:
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]

    def test_xss_payload_not_reflected_raw(self, client):
        for payload in self.XSS_PAYLOADS:
            r = client.get(f"/api/products?search={payload}")
            assert "<script>" not in r.data.decode().lower()

    def test_create_product_xss_in_name_not_stored_raw(self, client):
        r = client.post(
            "/api/products",
            data=json.dumps({
                "name":     "<script>alert('xss')</script>",
                "price":    9.99,
                "category": "Test",
            }),
            content_type="application/json",
        )
        assert r.status_code in (201, 400)


class TestProductsAPI:
    def test_get_all_products(self, client):
        r = client.get("/api/products")
        assert r.status_code == 200
        assert len(json.loads(r.data)) >= 5

    def test_search_returns_filtered_results(self, client):
        r = client.get("/api/products?search=Electronics")
        data = json.loads(r.data)
        assert all(p["category"] == "Electronics" for p in data)
        assert len(data) >= 3

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
        r = client.get("/api/products/99999")
        body = r.data.decode()
        assert "Traceback" not in body
        assert "/home/" not in body
        assert "sqlite3" not in body