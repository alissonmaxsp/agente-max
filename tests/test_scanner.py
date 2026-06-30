from src.security_scan import _detect_sql_error, _build_url_with_param
from src.nosql_scan import _detect_mongo_error, _build_url_with_raw


def test_detects_sql_errors_from_multiple_dbs():
    amostras = [
        "ERROR: syntax error at or near \"OR\"",            # Postgres
        '{"code":"PGRST301","message":"x"}',                # Supabase/PostgREST
        "You have an error in your SQL syntax",             # MySQL
        "Unclosed quotation mark after the character string",  # MSSQL
        "ORA-00933: SQL command not properly ended",        # Oracle
        "sqlite3.OperationalError: near \"x\"",             # SQLite
    ]
    for txt in amostras:
        assert _detect_sql_error(txt) is not None


def test_no_false_positive_on_normal_text():
    assert _detect_sql_error("Bem-vindo ao site! Produtos em destaque.") is None
    assert _detect_sql_error("") is None


def test_build_url_with_param_preserves_and_overrides():
    url = "https://ex.com/p?cat=1&page=2"
    out = _build_url_with_param(url, "cat", "1' OR '1'='1")
    assert "cat=1%27+OR" in out  # valor injetado e codificado
    assert "page=2" in out       # outros params preservados


def test_detects_mongo_errors():
    for txt in [
        "CastError: Cast to ObjectId failed",
        "MongoServerError: unknown operator: $foo",
        "E11000 duplicate key error collection",
    ]:
        assert _detect_mongo_error(txt) is not None
    assert _detect_mongo_error("Login realizado com sucesso") is None


def test_build_url_with_raw_adds_operator_param():
    out = _build_url_with_raw("https://api.x.com/u?id=1", "email[$ne]", "x")
    assert "id=1" in out
    assert "email[$ne]=x" in out


# ---- Avançados: JWT ----
import base64, json, hmac, hashlib
from src.auth_checks import analyze_token, _hs256_weak_secret


def _mk_jwt(header: dict, payload: dict, secret: str | None = None) -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    signing = f"{b64(header)}.{b64(payload)}"
    if secret is None:
        sig = "fakesig"
    else:
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
    return f"{signing}.{sig}"


def test_jwt_alg_none_is_critical():
    token = _mk_jwt({"alg": "none", "typ": "JWT"}, {"user": 1, "exp": 9999999999})
    types = [f["type"] for f in analyze_token(token)]
    assert "algoritmo 'none'" in types


def test_jwt_weak_secret_detected():
    token = _mk_jwt({"alg": "HS256", "typ": "JWT"}, {"user": 1, "exp": 9999999999}, secret="secret")
    assert _hs256_weak_secret(token) == "secret"
    types = [f["type"] for f in analyze_token(token)]
    assert "segredo HMAC fraco" in types


def test_jwt_missing_exp_flagged():
    token = _mk_jwt({"alg": "RS256", "typ": "JWT"}, {"user": 1})
    types = [f["type"] for f in analyze_token(token)]
    assert "sem expiração (exp)" in types


# ---- Sessão autenticada: extração de token ----
from src.auth_session import _find_token


def test_find_token_top_level_and_nested():
    assert _find_token({"access_token": "abc1234567890"}) == "abc1234567890"
    assert _find_token({"data": {"jwt": "xyz1234567890"}}) == "xyz1234567890"
    assert _find_token({"prefira": "Z"}, prefer_key="prefira") == "Z"
    assert _find_token({"nada": "x"}) is None
