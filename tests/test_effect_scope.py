"""E0710 broad-scope check — the SSRF-precondition guard.

Run: python3 tests/test_effect_scope.py   (exit 0 = pass)

The promise: a net.fetch effect whose host/authority is unpinned is
rejected at check time, because such a scope is what lets attacker-
controlled input steer a fetch to an internal endpoint (SSRF). Host-
pinned scopes — including path/query wildcards and *.subdomain pins —
pass untouched.
"""
from __future__ import annotations
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from aether.parser import parse                       # noqa: E402
from aether.passes.effects import (                   # noqa: E402
    check_effect_scope, check_fs_path_safety, check_secret_flow,
    check_injection, check_command_injection, check_pii_flow,
    check_authorization, check_resource_authorization, check_open_redirect,
    check_template_injection, check_deserialization, check_cleartext_transmission,
    check_metadata_fetch, check_hardcoded_secret, check_log_injection,
    check_reflected_xss, check_header_injection, check_xxe,
    check_csv_injection, check_marker_boundary, check_return_laundering,
    check_effects, check_unsatisfiable_refinement, _net_authority_wildcarded,
    check_code_injection,
)
from aether.passes.capability import check_capabilities  # noqa: E402


def _codes(src: str):
    ast = parse(src, "<scope>")
    return [d.code for d in check_effect_scope(ast)]


def _fs_codes(src: str):
    ast = parse(src, "<fs>")
    return [d.code for d in check_fs_path_safety(ast)]


# --- unit: the authority predicate, the heart of the check ------------

BROAD = [
    None,                                   # bare `net.fetch`
    "*",
    "https://*",
    "http://*/latest/meta-data/",
    "*://api.x/x",
    "ldap://*",
    "*/x",
    "*evil.com/x",
]
PINNED = [
    "https://api.x/charge/*",
    "https://api.payments.corp.example/v1/charge/*",
    "http://127.0.0.1:9999/*",
    "https://*.corp.example/*",            # subdomain pin: host bounded
    "https://api.x/v*/tracker/*",
    "https://other.com/x",
]


def test_authority_predicate():
    for a in BROAD:
        assert _net_authority_wildcarded(a) is not None, f"should flag: {a!r}"
    for a in PINNED:
        assert _net_authority_wildcarded(a) is None, f"should allow: {a!r}"
    print(f"E0710 unit: {len(BROAD)} broad flagged, {len(PINNED)} pinned allowed")


# --- integration: over an AST ------------------------------------------

def test_broad_rejected():
    src = """
function fetchUrl(url: String) returns String
  effects net.fetch("*")
do
  return url
end
"""
    assert _codes(src) == ["E0710"], "bare wildcard host must raise E0710"
    print("E0710 integration: unpinned net.fetch('*') rejected")


def test_scheme_only_rejected():
    src = """
function fetchUrl(url: String) returns String
  effects net.fetch("https://*")
do
  return url
end
"""
    assert _codes(src) == ["E0710"], "scheme-only host must raise E0710"
    print("E0710 integration: net.fetch('https://*') rejected")


def test_pinned_clean():
    src = """
function charge(id: Int) returns String
  effects net.fetch("https://api.payments.example/v1/charge/*")
do
  return "ok"
end
"""
    assert _codes(src) == [], "host-pinned scope must pass"
    print("E0710 integration: host-pinned scope passes clean")


def test_subdomain_pin_clean():
    src = """
function ingest() returns String
  effects net.fetch("https://*.corp.example/ingest")
do
  return "ok"
end
"""
    assert _codes(src) == [], "*.subdomain pin keeps host bounded"
    print("E0710 integration: *.subdomain pin passes clean")


# --- BUG-003: mixed-arg effect list must not crash the check -----------
# `effects net.fetch, net.fetch("https://...")` is legal: a path with no
# arg alongside the same path with one. Formatting the caller's effect
# list for an E0801 message sorted the entries themselves, so tuple
# comparison reached the Optional[str] arg slot and compared None with a
# str — an uncaught TypeError that killed the compiler instead of
# emitting the diagnostic it had already decided to emit.

def test_mixed_arg_effect_list_does_not_crash():
    src = """
function helper() returns Unit
  effects fs.write
do
  let _r: Result<Unit, String> = writeFile("/tmp/x", "y")
end

function go() returns Unit
  effects net.fetch, net.fetch("https://api.example.com/x")
do
  helper()
end
"""
    ast = parse(src, "<effmix>")
    diags = check_effects(ast)          # must not raise
    assert [d.code for d in diags] == ["E0801"], \
        "the uncovered fs.write must still be reported, not crash the pass"
    print("BUG-003: mixed-arg effect list formats instead of crashing")


# --- E0711 filesystem path-traversal precondition ----------------------

def _wf(pathexpr: str) -> str:
    return f"""
function save(name: String, data: String) returns Unit
  effects fs.write
do
  let _r: Result<Unit, String> = writeFile({pathexpr}, data)
end
"""


def test_fs_dynamic_path_rejected():
    assert _fs_codes(_wf('"uploads/" + name')) == ["E0711"], \
        "concatenated path must raise E0711"
    assert _fs_codes(_wf("name")) == ["E0711"], \
        "bare parameter path must raise E0711"
    print("E0711: dynamic writeFile path rejected")


def test_fs_literal_clean():
    assert _fs_codes(_wf('"/tmp/fixed.log"')) == [], "literal path is safe"
    print("E0711: literal writeFile path passes clean")


def test_fs_literal_dotdot_rejected():
    assert _fs_codes(_wf('"../secrets/x"')) == ["E0711"], \
        "literal path containing '..' must raise E0711"
    print("E0711: literal '..' path rejected")


def test_fs_safejoin_clean():
    assert _fs_codes(_wf('safeJoin("uploads", name)')) == [], \
        "safeJoin-sanitized path is safe"
    print("E0711: safeJoin-sanitized path passes clean")


def test_fs_readfile_covered():
    src = """
function load(name: String) returns String
  effects fs.read
do
  let r: Result<String, String> = readFile("data/" + name)
  return "x"
end
"""
    assert _fs_codes(src) == ["E0711"], "readFile dynamic path must raise E0711"
    print("E0711: dynamic readFile path rejected")


# --- E0712 secret-into-log (CWE-532) ------------------------------------

def _sec_codes(src: str):
    ast = parse(src, "<sec>")
    return [d.code for d in check_secret_flow(ast)]


def test_secret_logged_rejected():
    src = """
function login(pw: Secret<String>) returns Unit
  effects log
do
  print("pw=" + pw)
end
"""
    assert _sec_codes(src) == ["E0712"], "logging a Secret must raise E0712"
    print("E0712: secret into print rejected")


def test_secret_revealed_clean():
    src = """
function login(pw: Secret<String>) returns Unit
  effects log
do
  print("hash=" + reveal(pw))
end
"""
    assert _sec_codes(src) == [], "reveal() is the sanctioned disclosure"
    print("E0712: reveal() disclosure passes clean")


def test_secret_persisted_to_disk_rejected():
    src = """
function backup(token: Secret<String>) returns Unit
  effects fs.write
do
  let _r: Result<Unit, String> = writeFile("/tmp/creds", "t=" + token)
end
"""
    assert _sec_codes(src) == ["E0712"], "persisting a Secret to disk must raise E0712"
    print("E0712: secret into writeFile contents rejected")


def test_secret_disk_path_arg_not_flagged():
    # The secret in the PATH arg is out of scope; only contents (idx 1) is a sink.
    src = """
function backup(token: Secret<String>) returns Unit
  effects fs.write
do
  let _r: Result<Unit, String> = writeFile("/tmp/creds", "static")
end
"""
    assert _sec_codes(src) == [], "no secret reaches a sink here"
    print("E0712: non-leaking secret function passes clean")


def test_secret_taint_propagates():
    src = """
function login(pw: Secret<String>) returns Unit
  effects log
do
  let alias: Secret<String> = pw
  print("x=" + alias)
end
"""
    assert _sec_codes(src) == ["E0712"], "taint must propagate through let"
    print("E0712: taint propagates through binding")


def test_nonsecret_clean():
    src = """
function login(user: String) returns Unit
  effects log
do
  print("user=" + user)
end
"""
    assert _sec_codes(src) == [], "non-secret param must not be flagged"
    print("E0712: non-secret param passes clean")


# --- E0713 SQL injection (CWE-89) ---------------------------------------

def _sql_codes(src: str):
    ast = parse(src, "<sql>")
    return [d.code for d in check_injection(ast)]


def _q(expr: str) -> str:
    return f"""
function lookup(userId: String) returns String
  effects db.query
do
  return sqlQuery({expr})
end
"""


def test_sql_concat_rejected():
    assert _sql_codes(_q('"SELECT * FROM u WHERE id = " + userId')) == ["E0713"], \
        "concatenated query must raise E0713"
    print("E0713: concatenated query rejected")


def test_sql_bind_clean():
    assert _sql_codes(_q('sqlBind("SELECT * FROM u WHERE id = ?", userId)')) == [], \
        "sqlBind parameterized query is safe"
    print("E0713: sqlBind query passes clean")


def test_sql_literal_clean():
    assert _sql_codes(_q('"SELECT * FROM u LIMIT 10"')) == [], "literal query is safe"
    print("E0713: literal query passes clean")


def test_sql_bind_via_binding_clean():
    src = """
function lookup(userId: String) returns String
  effects db.query
do
  let q: String = sqlBind("SELECT * FROM u WHERE id = ?", userId)
  return sqlQuery(q)
end
"""
    assert _sql_codes(src) == [], "sqlBind result bound to a var is safe"
    print("E0713: sqlBind via binding passes clean")


# --- E0714 command injection (CWE-78) -------------------------------------

def _sh_codes(src: str):
    ast = parse(src, "<sh>")
    return [d.code for d in check_command_injection(ast)]


def _c(expr: str) -> str:
    return f"""
function convert(filename: String) returns String
  effects exec.run
do
  return shellExec({expr})
end
"""


def test_shell_concat_rejected():
    assert _sh_codes(_c('"convert " + filename + " out.png"')) == ["E0714"], \
        "concatenated command must raise E0714"
    print("E0714: concatenated command rejected")


def test_shell_arg_clean():
    assert _sh_codes(_c('shellArg("convert ? out.png", filename)')) == [], \
        "shellArg-quoted command is safe"
    print("E0714: shellArg command passes clean")


def test_shell_literal_clean():
    assert _sh_codes(_c('"ls -la /var/log"')) == [], "literal command is safe"
    print("E0714: literal command passes clean")


def test_shell_arg_via_binding_clean():
    src = """
function convert(filename: String) returns String
  effects exec.run
do
  let cmd: String = shellArg("convert ? out.png", filename)
  return shellExec(cmd)
end
"""
    assert _sh_codes(src) == [], "shellArg result bound to a var is safe"
    print("E0714: shellArg via binding passes clean")


# --- E0715 PII egress (data-residency / GDPR) ---------------------------

def _pii_codes(src: str):
    ast = parse(src, "<pii>")
    return [d.code for d in check_pii_flow(ast)]


def test_pii_logged_rejected():
    src = """
function track(email: PII<String>) returns Unit
  effects log
do
  print("user=" + email)
end
"""
    assert _pii_codes(src) == ["E0715"], "logging PII must raise E0715"
    print("E0715: PII into print rejected")


def test_pii_persisted_rejected():
    src = """
function track(email: PII<String>) returns Unit
  effects fs.write
do
  let _r: Result<Unit, String> = writeFile("/tmp/ev.log", "u=" + email)
end
"""
    assert _pii_codes(src) == ["E0715"], "persisting PII to disk must raise E0715"
    print("E0715: PII into writeFile contents rejected")


def test_pii_redacted_clean():
    src = """
function track(email: PII<String>) returns Unit
  effects log
do
  print("user=" + redact(email))
end
"""
    assert _pii_codes(src) == [], "redact() is the sanctioned masking exit"
    print("E0715: redact() masking passes clean")


def test_pii_path_arg_not_flagged():
    # PII in the PATH arg (index 0) is out of scope; only contents (1) is a sink.
    src = """
function track(email: PII<String>) returns Unit
  effects fs.write
do
  let _r: Result<Unit, String> = writeFile("/tmp/ev.log", "static")
end
"""
    assert _pii_codes(src) == [], "no PII reaches a sink here"
    print("E0715: non-leaking PII function passes clean")


# --- E0716 missing authorization before mutation (CWE-862) ---------------

def _authz_codes(src: str):
    ast = parse(src, "<authz>")
    return [d.code for d in check_authorization(ast)]


def test_mutation_without_auth_rejected():
    src = """
function cancelOrder(orderId: String) returns Unit
  effects db.exec
do
  let _r: String = sqlExec(sqlBind("UPDATE orders SET s='c' WHERE id = ?", orderId))
end
"""
    assert _authz_codes(src) == ["E0716"], "mutation with no auth arg must raise E0716"
    print("E0716: sqlExec without an auth argument rejected")


def test_unproven_auth_token_rejected():
    src = """
function cancelOrder(orderId: String, who: String) returns Unit
  effects db.exec
do
  let _r: String = sqlExec("UPDATE orders SET s='c' WHERE id = 1", who)
end
"""
    assert _authz_codes(src) == ["E0716"], "a plain String is not an authorization proof"
    print("E0716: unproven token rejected")


def test_direct_authorize_clean():
    src = """
function cancelOrder(user: String) returns Unit
  effects db.exec
do
  let _r: String = sqlExec("UPDATE orders SET s='c' WHERE id = 1", authorize(user, "orders:cancel"))
end
"""
    assert _authz_codes(src) == [], "a direct authorize(...) call is the proof"
    print("E0716: direct authorize(...) passes clean")


def test_authorize_via_binding_clean():
    src = """
function cancelOrder(user: String) returns Unit
  effects db.exec
do
  let tok: Authorized<String> = authorize(user, "orders:cancel")
  let _r: String = sqlExec("UPDATE orders SET s='c' WHERE id = 1", tok)
end
"""
    assert _authz_codes(src) == [], "an authorize(...) result bound to a name is a proof"
    print("E0716: authorize via binding passes clean")


def test_authorized_param_clean():
    src = """
function cancelOrder(auth: Authorized<String>) returns Unit
  effects db.exec
do
  let _r: String = sqlExec("UPDATE orders SET s='c' WHERE id = 1", auth)
end
"""
    assert _authz_codes(src) == [], "an Authorized<T> param carries the caller's proof"
    print("E0716: Authorized<T> parameter passes clean")


def test_launder_via_authorized_param_rejected():
    # The nominal-provenance fix: a helper's Authorized<T> parameter does
    # not discharge the obligation — a raw String is refused at the call
    # site, so no unproven value can ever reach a trusted parameter.
    src = """
function doDelete(auth: Authorized<String>) returns Unit
  effects db.exec
do
  let _r: String = sqlExec("DELETE FROM users WHERE id = 1", auth)
end

function main(who: String) returns Unit
  effects db.exec
do
  doDelete(who)
end
"""
    assert _authz_codes(src) == ["E0716"], \
        "a raw String into an Authorized<T> parameter must raise E0716"
    print("E0716: laundering via Authorized<T> parameter rejected")


def test_assign_demotes_authorized_binding():
    # `tok = who` is a binding too (Assign carries "target", not "name");
    # one non-proof binding disqualifies the name.
    src = """
function cancelOrder(user: String, who: String) returns Unit
  effects db.exec
do
  let tok: Authorized<String> = authorize(user, "orders:cancel")
  tok = who
  let _r: String = sqlExec("UPDATE orders SET s='c' WHERE id = 1", tok)
end
"""
    codes = _authz_codes(src)
    assert "E0716" in codes, "a rebound proof name must be demoted"
    print("E0716: reassignment demotes a proven name")


def test_var_bound_authorize_clean():
    # `var` bindings are proofs too — only Let/Assign were collected before.
    src = """
function cancelOrder(user: String) returns Unit
  effects db.exec
do
  var tok: Authorized<String> = authorize(user, "orders:cancel")
  let _r: String = sqlExec("UPDATE orders SET s='c' WHERE id = 1", tok)
end
"""
    assert _authz_codes(src) == [], "a var-bound authorize(...) is a proof"
    print("E0716: var-bound authorize passes clean")


def test_annotation_cannot_mint_authorized():
    # `let p: Authorized<String> = raw` is refused even with no sink —
    # the annotation cannot mint the type.
    src = """
function main(who: String) returns Unit
  effects pure
do
  let p: Authorized<String> = who
end
"""
    assert _authz_codes(src) == ["E0716"], \
        "String -> Authorized<String> coercion must raise E0716"
    print("E0716: annotation coercion rejected")


def test_authorize_resource_is_a_proof_for_e0716():
    # authorizeResource is the resource-bound strengthening of authorize;
    # its id-binding is E0717's job, but it IS an Authorized<T> proof.
    src = """
function updateDoc(docId: String, user: String) returns Unit
  effects db.exec
do
  let proof: Authorized<String> = authorizeResource(user, "docs:edit", docId)
  let _r: String = sqlExec("UPDATE docs SET x=1 WHERE id = 1", proof)
end
"""
    assert _authz_codes(src) == [], "authorizeResource mints Authorized<T>"
    print("E0716: authorizeResource accepted as a proof")


def test_result_wrapped_proof_via_match_clean():
    # The verify-then-mint shape: the proof travels in Result<Authorized<T>,E>
    # and unwraps through `match ... case Ok(proof)`.
    src = """
function verify(token: String) returns Result<Authorized<String>, String>
  effects pure
do
  if token == "good" then
    return Ok(authorize(token, "authenticated"))
  end
  return Err("bad token")
end

function main(token: String) returns Unit
  effects db.exec
do
  let v = verify(token)
  match v do
    case Ok(proof) do
      let _r: String = sqlExec("DELETE FROM t WHERE id = 1", proof)
    end
    case Err(e) do
      return
    end
  end
end
"""
    assert _authz_codes(src) == [], \
        "an Ok-unwrapped proof from a Result minter is a proof"
    print("E0716: Result-wrapped proof via match passes clean")


def test_fake_minter_return_rejected():
    # The return type is a promise: a minter that returns a raw value
    # (directly or wrapped in Ok) is refused at the return site.
    direct = """
function fake(raw: String) returns Authorized<String>
  effects pure
do
  return raw
end
"""
    wrapped = """
function fake(raw: String) returns Result<Authorized<String>, String>
  effects pure
do
  return Ok(raw)
end
"""
    assert _authz_codes(direct) == ["E0716"], \
        "returning raw from an Authorized-returning fn must raise E0716"
    assert _authz_codes(wrapped) == ["E0716"], \
        "returning Ok(raw) from a Result minter must raise E0716"
    print("E0716: fake minter return sites rejected")


def test_match_on_unproven_result_rejected():
    # Ok-unwrapping only grants a proof when the scrutinee provably
    # carries one; a plain Result<String, _> grants nothing.
    src = """
function main(r: Result<String, String>, stmt: String) returns Unit
  effects db.exec
do
  match r do
    case Ok(p) do
      let _x: String = sqlExec(stmt, p)
    end
    case Err(e) do
      return
    end
  end
end
"""
    assert _authz_codes(src) == ["E0716"], \
        "Ok-binding from an unproven Result is not a proof"
    print("E0716: match on unproven Result rejected")


def test_gated_function_escape_rejected():
    # A function taking Authorized<T> used as a VALUE would allow
    # indirect calls the call-site check cannot see.
    src = """
function doDelete(auth: Authorized<String>) returns Unit
  effects db.exec
do
  let _r: String = sqlExec("DELETE FROM t", auth)
end

function main(user: String) returns Unit
  effects db.exec
do
  let f = doDelete
end
"""
    assert _authz_codes(src) == ["E0716"], \
        "an Authorized-gated function escaping as a value must raise E0716"
    print("E0716: gated function escaping as a value rejected")


def test_sqlexec_concat_query_rejected_by_injection():
    # The mutating sink's QUERY arg stays under the E0713 injection rule.
    src = """
function cancelOrder(orderId: String, auth: Authorized<String>) returns Unit
  effects db.exec
do
  let _r: String = sqlExec("UPDATE orders SET s='c' WHERE id = " + orderId, auth)
end
"""
    ast = parse(src, "<authz-inj>")
    assert [d.code for d in check_injection(ast)] == ["E0713"], \
        "sqlExec's query arg must be covered by E0713"
    print("E0716/E0713: concatenated sqlExec query rejected by E0713")


# --- E0717 IDOR / cross-tenant resource binding (CWE-639) -----------------

def _idor_codes(src: str):
    ast = parse(src, "<idor>")
    return [d.code for d in check_resource_authorization(ast)]


def test_wrong_resource_rejected():
    # The IDOR shape: authorization named requestedId, sink mutates victimId.
    src = """
function updateDoc(requestedId: String, victimId: String, user: String) returns Unit
  effects db.exec
do
  let proof: Authorized<String> = authorizeResource(user, "docs:edit", requestedId)
  let _r: String = sqlByOwner("UPDATE docs SET b='x' WHERE id = ?", victimId, proof)
end
"""
    assert _idor_codes(src) == ["E0717"], "a proof for a DIFFERENT id must raise E0717"
    print("E0717: proof bound to a different resource id rejected")


def test_same_resource_direct_clean():
    src = """
function updateDoc(docId: String, user: String) returns Unit
  effects db.exec
do
  let _r: String = sqlByOwner("UPDATE docs SET b='x' WHERE id = ?", docId, authorizeResource(user, "docs:edit", docId))
end
"""
    assert _idor_codes(src) == [], "same stable id in guard and sink is the proof"
    print("E0717: direct authorizeResource on the same id passes clean")


def test_same_resource_via_binding_clean():
    src = """
function updateDoc(docId: String, user: String) returns Unit
  effects db.exec
do
  let proof: Authorized<String> = authorizeResource(user, "docs:edit", docId)
  let _r: String = sqlByOwner("UPDATE docs SET b='x' WHERE id = ?", docId, proof)
end
"""
    assert _idor_codes(src) == [], "a bound authorizeResource proof for the same id is accepted"
    print("E0717: proof via binding on the same id passes clean")


def test_same_literal_clean_different_literal_rejected():
    clean = """
function pinShip() returns Unit
  effects db.exec
do
  let _r: String = sqlByOwner("UPDATE t SET s='x' WHERE id = '42'", "42", authorizeResource("svc", "t:edit", "42"))
end
"""
    bad = """
function pinShip() returns Unit
  effects db.exec
do
  let _r: String = sqlByOwner("UPDATE t SET s='x' WHERE id = '99'", "99", authorizeResource("svc", "t:edit", "42"))
end
"""
    assert _idor_codes(clean) == [], "identical literal ids match"
    assert _idor_codes(bad) == ["E0717"], "different literal ids must raise E0717"
    print("E0717: literal id matching (equal clean, unequal rejected)")


def test_rebound_id_rejected():
    # docId is reassigned between the guard and the sink: the name no
    # longer witnesses one value, so identity cannot be proven.
    src = """
function updateDoc(docId: String, user: String) returns Unit
  effects db.exec
do
  let proof: Authorized<String> = authorizeResource(user, "docs:edit", docId)
  docId = "doc-9999"
  let _r: String = sqlByOwner("UPDATE docs SET b='x' WHERE id = ?", docId, proof)
end
"""
    assert _idor_codes(src) == ["E0717"], "a rebound id name must be refused (identity unprovable)"
    print("E0717: rebound resource id rejected")


def test_unbound_proof_rejected():
    # A plain authorize(...) (E0716's proof) names NO resource — not enough here.
    src = """
function updateDoc(docId: String, user: String) returns Unit
  effects db.exec
do
  let proof: Authorized<String> = authorize(user, "docs:edit")
  let _r: String = sqlByOwner("UPDATE docs SET b='x' WHERE id = ?", docId, proof)
end
"""
    assert _idor_codes(src) == ["E0717"], "a resource-less authorize(...) is not a bound proof"
    print("E0717: resource-less authorize proof rejected")


def test_missing_proof_rejected():
    src = """
function updateDoc(docId: String) returns Unit
  effects db.exec
do
  let _r: String = sqlByOwner("UPDATE docs SET b='x' WHERE id = ?", docId)
end
"""
    assert _idor_codes(src) == ["E0717"], "omitting the proof must raise E0717"
    print("E0717: missing proof argument rejected")


def test_sqlbyowner_concat_stmt_rejected_by_injection():
    # The resource-scoped sink's STMT arg stays under the E0713 injection rule.
    src = """
function updateDoc(docId: String, user: String) returns Unit
  effects db.exec
do
  let _r: String = sqlByOwner("UPDATE docs SET b='x' WHERE id = " + docId, docId, authorizeResource(user, "docs:edit", docId))
end
"""
    ast = parse(src, "<idor-inj>")
    assert [d.code for d in check_injection(ast)] == ["E0713"], \
        "sqlByOwner's stmt arg must be covered by E0713"
    print("E0717/E0713: concatenated sqlByOwner stmt rejected by E0713")


# --- E0718 open redirect (CWE-601) --------------------------------------

def _redir_codes(src: str):
    ast = parse(src, "<redir>")
    return [d.code for d in check_open_redirect(ast)]


def _r(expr: str) -> str:
    return f"""
function login(returnTo: String) returns String
  effects net.redirect
do
  return redirect({expr})
end
"""


def test_redirect_dynamic_rejected():
    assert _redir_codes(_r("returnTo")) == ["E0718"], "bare param target must raise E0718"
    assert _redir_codes(_r('"https://" + returnTo')) == ["E0718"], \
        "concatenated target must raise E0718"
    print("E0718: dynamic redirect target rejected")


def test_redirect_literal_clean():
    assert _redir_codes(_r('"/dashboard"')) == [], "literal target is safe"
    print("E0718: literal redirect target passes clean")


def test_redirect_safe_clean():
    assert _redir_codes(_r('safeRedirect("app.example.com", returnTo)')) == [], \
        "safeRedirect-pinned target is safe"
    print("E0718: safeRedirect target passes clean")


def test_redirect_safe_via_binding_clean():
    src = """
function login(returnTo: String) returns String
  effects net.redirect
do
  let target: String = safeRedirect("app.example.com", returnTo)
  return redirect(target)
end
"""
    assert _redir_codes(src) == [], "safeRedirect result bound to a var is safe"
    print("E0718: safeRedirect via binding passes clean")


# --- E0719 server-side template injection (SSTI, CWE-94) ----------------

def _tmpl_codes(src: str):
    ast = parse(src, "<tmpl>")
    return [d.code for d in check_template_injection(ast)]


def _t(expr: str) -> str:
    return f"""
function render(userInput: String) returns String
  effects pure
do
  return renderTemplate({expr}, userInput)
end
"""


def test_template_concat_rejected():
    assert _tmpl_codes(_t('"Hi " + userInput')) == ["E0719"], \
        "template built by concatenation must raise E0719"
    print("E0719: concatenated template rejected")


def test_template_param_rejected():
    assert _tmpl_codes(_t("userInput")) == ["E0719"], \
        "bare-parameter template must raise E0719"
    print("E0719: parameter-as-template rejected")


def test_template_literal_clean():
    assert _tmpl_codes(_t('"Hello {}, welcome"')) == [], \
        "fixed literal template is safe (data goes in arg 2)"
    print("E0719: literal template passes clean")


def test_template_literal_binding_clean():
    src = """
function render(userInput: String) returns String
  effects pure
do
  let tmpl: String = "Hello {}"
  return renderTemplate(tmpl, userInput)
end
"""
    assert _tmpl_codes(src) == [], "template bound to a literal is safe"
    print("E0719: literal-bound template passes clean")


def test_template_trusted_clean():
    src = """
function render(bundleTemplate: String, userInput: String) returns String
  effects pure
do
  return renderTemplate(trusted(bundleTemplate), userInput)
end
"""
    assert _tmpl_codes(src) == [], "trusted(...) is the explicit trust boundary"
    print("E0719: trusted(...) dynamic template passes clean")


# --- E0720 insecure deserialization (CWE-502) ---------------------------

def _deser_codes(src: str):
    ast = parse(src, "<deser>")
    return [d.code for d in check_deserialization(ast)]


def test_deserialize_untrusted_rejected():
    src = """
function loadSession(raw: String) returns String
  effects pure
do
  return deserialize(raw)
end
"""
    assert _deser_codes(src) == ["E0720"], "deserialize on untrusted data must raise E0720"
    print("E0720: untrusted deserialize rejected")


def test_deserialize_concat_rejected():
    src = """
function loadSession(raw: String) returns String
  effects pure
do
  return deserialize("prefix" + raw)
end
"""
    assert _deser_codes(src) == ["E0720"], "deserialize on concatenated data must raise E0720"
    print("E0720: concatenated deserialize rejected")


def test_schema_decode_clean():
    src = """
function loadSession(raw: String) returns String
  effects pure
do
  return schemaDecode("SessionV1", raw)
end
"""
    assert _deser_codes(src) == [], "schemaDecode is the sanctioned decoder"
    print("E0720: schemaDecode passes clean")


def test_deserialize_literal_clean():
    src = """
function loadFixture() returns String
  effects pure
do
  return deserialize("trusted-constant-blob")
end
"""
    assert _deser_codes(src) == [], "deserializing a trusted literal is safe"
    print("E0720: literal deserialize passes clean")


def test_deserialize_trusted_clean():
    src = """
function loadConfig(configBlob: String) returns String
  effects pure
do
  return deserialize(trusted(configBlob))
end
"""
    assert _deser_codes(src) == [], "trusted(...) clears the deserialize sink"
    print("E0720: trusted(...) dynamic deserialize passes clean")


# --- E0721 cleartext transmission (CWE-319) -----------------------------

def _ct_codes(src: str):
    ast = parse(src, "<ct>")
    return [d.code for d in check_cleartext_transmission(ast)]


def test_cleartext_http_rejected():
    src = """
function send(data: String) returns String
  effects net.fetch("http://api.corp.example/ingest/*")
do
  return data
end
"""
    assert _ct_codes(src) == ["E0721"], "cleartext http:// to a real host must raise E0721"
    print("E0721: cleartext http:// rejected")


def test_https_clean():
    src = """
function send(data: String) returns String
  effects net.fetch("https://api.corp.example/ingest/*")
do
  return data
end
"""
    assert _ct_codes(src) == [], "https:// is encrypted, no E0721"
    print("E0721: https:// passes clean")


def test_loopback_http_clean():
    src = """
function a(d: String) returns String
  effects net.fetch("http://127.0.0.1:9999/*")
do
  return d
end
function b(d: String) returns String
  effects net.fetch("http://localhost:8080/x")
do
  return d
end
"""
    assert _ct_codes(src) == [], "loopback http is exempt (never leaves the host)"
    print("E0721: loopback http passes clean")


# --- E0722 metadata-endpoint fetch (CWE-918) ----------------------------

def _md_codes(src: str):
    ast = parse(src, "<md>")
    return [d.code for d in check_metadata_fetch(ast)]


def test_metadata_ip_rejected():
    src = """
function steal() returns String
  effects net.fetch("https://169.254.169.254/latest/meta-data/iam/*")
do
  return "creds"
end
"""
    assert _md_codes(src) == ["E0722"], "link-local metadata fetch must raise E0722"
    print("E0722: metadata IP fetch rejected")


def test_link_local_range_rejected():
    # Any 169.254.x.x host, not only .169.254.
    src = """
function probe() returns String
  effects net.fetch("http://169.254.1.1/x")
do
  return "x"
end
"""
    assert _md_codes(src) == ["E0722"], "any 169.254.0.0/16 host must raise E0722"
    print("E0722: link-local range rejected")


def test_normal_host_not_metadata():
    src = """
function ok(d: String) returns String
  effects net.fetch("https://api.corp.example/v1/*")
do
  return d
end
"""
    assert _md_codes(src) == [], "a normal host is not a metadata fetch"
    print("E0722: normal host passes clean")


# --- E0723 hardcoded credential (CWE-798) -------------------------------

def _hc_codes(src: str):
    ast = parse(src, "<hc>")
    return [d.code for d in check_hardcoded_secret(ast)]


def test_aws_key_rejected():
    src = """
function client() returns String
  effects pure
do
  return "AKIAIOSFODNN7EXAMPLE"
end
"""
    assert _hc_codes(src) == ["E0723"], "hardcoded AWS key must raise E0723"
    print("E0723: AWS access key rejected")


def test_github_token_rejected():
    src = """
function client() returns String
  effects pure
do
  return "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
end
"""
    assert _hc_codes(src) == ["E0723"], "hardcoded GitHub token must raise E0723"
    print("E0723: GitHub token rejected")


def test_demo_password_clean():
    # Low-entropy demo strings must NOT match — keeps the check non-noisy.
    src = """
function demo() returns Secret<String>
  effects pure
do
  return classify("hunter2")
end
"""
    assert _hc_codes(src) == [], "a demo password is not a provider credential"
    print("E0723: demo password passes clean")


def test_env_sourced_clean():
    src = """
function client(key: Secret<String>) returns Secret<String>
  effects pure
do
  return key
end
"""
    assert _hc_codes(src) == [], "an env-sourced secret has no literal to match"
    print("E0723: env-sourced secret passes clean")


# --- E0724 log injection (CWE-117) --------------------------------------

def _li_codes(src: str):
    ast = parse(src, "<li>")
    return [d.code for d in check_log_injection(ast)]


def test_untrusted_logged_rejected():
    src = """
function handle(userInput: Untrusted<String>) returns Unit
  effects log
do
  print("req: " + userInput)
end
"""
    assert _li_codes(src) == ["E0724"], "logging an Untrusted value must raise E0724"
    print("E0724: untrusted into log rejected")


def test_sanitized_log_clean():
    src = """
function handle(userInput: Untrusted<String>) returns Unit
  effects log
do
  print("req: " + sanitizeLog(userInput))
end
"""
    assert _li_codes(src) == [], "sanitizeLog is the sanctioned exit"
    print("E0724: sanitizeLog passes clean")


def test_trusted_string_not_flagged():
    src = """
function handle(msg: String) returns Unit
  effects log
do
  print("req: " + msg)
end
"""
    assert _li_codes(src) == [], "a plain String param is not Untrusted"
    print("E0724: plain string passes clean")


# --- E0725 reflected XSS (CWE-79) ---------------------------------------

def _xss_codes(src: str):
    ast = parse(src, "<xss>")
    return [d.code for d in check_reflected_xss(ast)]


def test_untrusted_html_rejected():
    src = """
function page(userInput: Untrusted<String>) returns String
  effects pure
do
  return htmlResponse("<div>" + userInput + "</div>")
end
"""
    assert _xss_codes(src) == ["E0725"], "untrusted into HTML must raise E0725"
    print("E0725: untrusted into HTML rejected")


def test_html_escape_clean():
    src = """
function page(userInput: Untrusted<String>) returns String
  effects pure
do
  return htmlResponse("<div>" + htmlEscape(userInput) + "</div>")
end
"""
    assert _xss_codes(src) == [], "htmlEscape is the sanctioned exit"
    print("E0725: htmlEscape passes clean")


def test_wrong_sanitizer_still_xss():
    # sanitizeLog clears E0724 but must NOT clear E0725 — per-sink exits.
    src = """
function page(userInput: Untrusted<String>) returns String
  effects pure
do
  return htmlResponse("<div>" + sanitizeLog(userInput) + "</div>")
end
"""
    assert _xss_codes(src) == ["E0725"], "sanitizeLog does not neutralize HTML"
    print("E0725: wrong sanitizer (sanitizeLog) still flagged")


# --- E0726 HTTP response splitting / header injection (CWE-113) ----------

def _hi_codes(src: str):
    ast = parse(src, "<hi>")
    return [d.code for d in check_header_injection(ast)]


def test_untrusted_header_rejected():
    src = """
function respond(userLang: Untrusted<String>) returns Unit
  effects log
do
  let _r: Unit = setHeader("Content-Language", userLang)
end
"""
    assert _hi_codes(src) == ["E0726"], "untrusted header value must raise E0726"
    print("E0726: untrusted header rejected")


def test_sanitize_header_clean():
    src = """
function respond(userLang: Untrusted<String>) returns Unit
  effects log
do
  let _r: Unit = setHeader("Content-Language", sanitizeHeader(userLang))
end
"""
    assert _hi_codes(src) == [], "sanitizeHeader is the sanctioned exit"
    print("E0726: sanitizeHeader passes clean")


# --- E0727 XML external entity / XXE (CWE-611) --------------------------

def _xxe_codes(src: str):
    ast = parse(src, "<xxe>")
    return [d.code for d in check_xxe(ast)]


def test_untrusted_xml_rejected():
    src = """
function loadDoc(raw: String) returns String
  effects pure
do
  return parseXml(raw)
end
"""
    assert _xxe_codes(src) == ["E0727"], "parseXml on untrusted data must raise E0727"
    print("E0727: untrusted parseXml rejected")


def test_parse_xml_safe_clean():
    src = """
function loadDoc(raw: String) returns String
  effects pure
do
  return parseXmlSafe(raw)
end
"""
    assert _xxe_codes(src) == [], "parseXmlSafe is the sanctioned parser"
    print("E0727: parseXmlSafe passes clean")


# --- E0728 CSV / formula injection (CWE-1236) ---------------------------

def _csv_codes(src: str):
    ast = parse(src, "<csv>")
    return [d.code for d in check_csv_injection(ast)]


def test_untrusted_csv_rejected():
    src = """
function export(cell: Untrusted<String>) returns String
  effects pure
do
  return csvCell(cell)
end
"""
    assert _csv_codes(src) == ["E0728"], "untrusted CSV cell must raise E0728"
    print("E0728: untrusted CSV cell rejected")


def test_csv_escape_clean():
    src = """
function export(cell: Untrusted<String>) returns String
  effects pure
do
  return csvCell(csvEscape(cell))
end
"""
    assert _csv_codes(src) == [], "csvEscape is the sanctioned exit"
    print("E0728: csvEscape passes clean")


# --- composition: all reach-scope detectors fire additively -------------

def test_detectors_compose_additively():
    """One module with seven independent violations must yield all seven
    codes — no pass masks another. Runs the whole registry, not a local
    copy of it."""
    import os
    from aether.passes import analyze_flat
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "..", "demos", "case_studies",
                        "composition_kitchen_sink", "aether", "multi_violation.aeth")
    with open(path, encoding="utf-8") as f:
        ast = parse(f.read(), "<kitchen>")
    codes = {d.code for d in analyze_flat(ast)}
    expected = {"E0712", "E0713", "E0719", "E0720", "E0721", "E0722", "E0723"}
    assert expected <= codes, f"missing {expected - codes}; got {sorted(codes)}"
    print(f"composition: all 7 detectors fired together ({len(codes)} codes)")


# --- Iter 39: marker-returning calls seed taint (Gap A) -----------------
# Taint must also originate at calls to functions whose declared return
# type carries the marker (stdlib constructors + user declarations) —
# signature-level interprocedural seeding; bodies are not analyzed.

SECRET_RETURN_SRC = """
function getToken() returns Secret<String>
  effects pure
do
  return classify("tok_live_secret")
end

function main() returns Unit
  effects log
do
  let t: Secret<String> = getToken()
  print("token=" + t)
end
"""


def test_secret_return_taint_rejected():
    assert "E0712" in _sec_codes(SECRET_RETURN_SRC), \
        "a Secret returned from a call must taint the binding"
    print("E0712: secret via return type rejected")


def test_secret_inline_source_call_rejected():
    src = """
function getToken() returns Secret<String>
  effects pure
do
  return classify("tok_live_secret")
end

function main() returns Unit
  effects log
do
  print("token=" + getToken())
end
"""
    assert "E0712" in _sec_codes(src), \
        "an inline call returning Secret must be a leak at the sink"
    print("E0712: inline secret-returning call rejected")


def test_secret_return_revealed_clean():
    src = """
function getToken() returns Secret<String>
  effects pure
do
  return classify("tok_live_secret")
end

function main() returns Unit
  effects log
do
  print("token=" + reveal(getToken()))
end
"""
    assert _sec_codes(src) == [], "reveal() prunes the source call"
    print("E0712: reveal(sourceCall()) passes clean")


def test_classify_inline_rejected():
    src = """
function main() returns Unit
  effects log
do
  print("pw=" + classify("hunter2"))
end
"""
    assert "E0712" in _sec_codes(src), \
        "classify() is the stdlib Secret constructor - inline log is a leak"
    print("E0712: inline classify() into print rejected")


def test_pii_return_taint_rejected():
    src = """
function fetchUser() returns PII<String>
  effects pure
do
  return classifyPII("alice@example.com")
end

function main() returns Unit
  effects log
do
  let u: PII<String> = fetchUser()
  print("user=" + u)
end
"""
    assert "E0715" in _pii_codes(src), \
        "a PII value returned from a call must taint the binding"
    print("E0715: PII via return type rejected")


def test_untrusted_return_taint_rejected():
    src = """
function readForm() returns Untrusted<String>
  effects pure
do
  return classifyUntrusted("evil injected")
end

function main() returns Unit
  effects log
do
  let v: Untrusted<String> = readForm()
  print("got " + v)
end
"""
    assert "E0724" in _li_codes(src), \
        "an Untrusted returned from a call must taint the binding"
    print("E0724: untrusted via return type rejected")


def test_plain_return_still_clean():
    src = """
function greet() returns String
  effects pure
do
  return "hello"
end

function main() returns Unit
  effects log
do
  let g: String = greet()
  print(g)
end
"""
    assert _sec_codes(src) == [] and _li_codes(src) == [], \
        "non-marker returns must not seed taint (non-breaking)"
    print("E0712/E0724: plain String return stays clean")


# --- container-carried markers: nested in generic arguments -------------
# `List<PII<String>>` carries the marker one level down. Matching only at
# the top of the type node made every such param untainted, so a sink read
# it in the clear. `_type_carries_marker` searches the whole type tree for
# the three TAINT markers; `Authorized<T>` deliberately keeps the
# top-level-only rule (widening a PROOF marker relaxes acceptance).

def test_list_of_pii_param_tainted():
    src = """
function leak(xs: List<PII<String>>) returns Unit
  effects log
do
  print("all=" + toString(xs))
end
"""
    assert "E0715" in _pii_codes(src), \
        "a PII marker nested in List<...> must still taint the param"
    print("E0715: List<PII<String>> param tainted")


def test_option_of_secret_param_tainted():
    src = """
function leak(o: Option<Secret<String>>) returns Unit
  effects log
do
  print("tok=" + toString(o))
end
"""
    assert "E0712" in _sec_codes(src), \
        "a Secret marker nested in Option<...> must still taint the param"
    print("E0712: Option<Secret<String>> param tainted")


def test_nested_marker_param_crossing_sanctioned():
    src = """
function sink(ys: List<PII<String>>) returns Unit
  effects log
do
  print("n=" + toString(ys))
end

function main(xs: List<PII<String>>) returns Unit
  effects log
do
  sink(xs)
end
"""
    assert _mb_codes(src) == [], \
        "a callee param carrying the marker nested is the sanctioned crossing"
    print("E0729: nested-marker param crossing passes clean")


def test_nested_marker_return_type_clean():
    src = """
function collect(x: PII<String>) returns List<PII<String>>
  effects pure
do
  return [x]
end
"""
    assert _rl_codes(src) == [], \
        "a return type carrying the marker nested is an honest signature"
    print("E0730: nested-marker return type passes clean")


def test_nested_authorized_still_unproven():
    src = """
function cancelOrder(auths: List<Authorized<String>>) returns Unit
  effects db.exec
do
  let _r: String = sqlExec("UPDATE orders SET s='c' WHERE id = 1", auths)
end
"""
    assert _authz_codes(src) == ["E0716"], \
        "Authorized<T> is a PROOF marker - nesting must NOT count as proof"
    print("E0716: nested Authorized<T> is not a proof (top-level rule kept)")


# --- container-carried markers: record fields ---------------------------
# `record User do email: PII<String> end` declares that the record CARRIES
# PII in that field. Two duties follow: reading `u.email` is a taint
# source (or the sinks go blind), and putting a marked value INTO that
# field is a sanctioned crossing (or the record can never legitimately
# hold PII and the safe shape is unwritable). Field matching is by NAME —
# no record-type resolution — so it over-flags a same-named plain field.

RECORD_PII_SRC = """
record User do
  email: PII<String>
  name: String
end

function leak(u: User) returns Unit
  effects log
do
  print("user=" + u.email)
end
"""


def test_record_field_read_tainted():
    assert _pii_codes(RECORD_PII_SRC) == ["E0715"], \
        "reading a PII-typed record field must taint at the sink"
    print("E0715: PII record field read into a log rejected")


def test_record_field_read_redacted_clean():
    src = """
record User do
  email: PII<String>
  name: String
end

function leak(u: User) returns Unit
  effects log
do
  print("user=" + redact(u.email))
end
"""
    assert _pii_codes(src) == [], \
        "redact() on the field read is the sanctioned exit"
    print("E0715: redacted record field read passes clean")


def test_record_field_bound_then_leaked():
    src = """
record Creds do
  token: Secret<String>
end

function leak(c: Creds) returns Unit
  effects log
do
  let t: String = c.token
  print("tok=" + t)
end
"""
    assert "E0712" in _sec_codes(src), \
        "a name bound to a marked field read must inherit the taint"
    print("E0712: Secret record field via binding rejected")


def test_plain_record_field_still_clean():
    src = """
record Event do
  action: String
end

function report(e: Event) returns Unit
  effects log
do
  print("action=" + e.action)
end
"""
    assert _pii_codes(src) == [] and _sec_codes(src) == [], \
        "a record with no marker-typed field must stay clean (non-breaking)"
    print("E0715/E0712: plain record fields stay clean")


def test_record_construction_is_sanctioned_crossing():
    src = """
record User do
  email: PII<String>
  name: String
end

function leak(u: User) returns Unit
  effects log
do
  print("user=" + redact(u.email))
end

function main() returns Unit
  effects log
do
  leak(User(classifyPII("jane@corp.example"), "jane"))
end
"""
    assert _mb_codes(src) == [], \
        "a marker-typed FIELD preserves the marker - the crossing is sanctioned"
    print("E0729: construction into a marker-typed field passes clean")


def test_record_return_is_not_laundering():
    src = """
record User do
  email: PII<String>
  name: String
end

function build(e: PII<String>) returns User
  effects pure
do
  return User(e, "jane")
end
"""
    assert _rl_codes(src) == [], \
        "returning a record whose FIELD carries the marker is honest"
    print("E0730: record return with a marker-typed field passes clean")


def test_record_unmarked_field_still_launders():
    src = """
record Event do
  who: String
end

function build(e: PII<String>) returns Event
  effects pure
do
  return Event(e)
end
"""
    assert _rl_codes(src) == ["E0730"], \
        "a PLAIN field erases the marker - that is still laundering"
    print("E0730: construction into a plain field still rejected")


# --- E0729 marker laundering across a user-function boundary ------------
# A Secret/PII/Untrusted value passed to a user-declared callee parameter
# NOT typed with that marker erases the marker inside the callee — every
# sink pass goes blind. Sanctioned exits: the marker's unwrappers at the
# call site, or a marker-typed parameter.

def _mb_codes(src: str):
    ast = parse(src, "<mb>")
    return [d.code for d in check_marker_boundary(ast)]


LAUNDER_SRC = """
function logIt(msg: String) returns Unit
  effects log
do
  print(msg)
end

function main(password: Secret<String>) returns Unit
  effects log
do
  logIt(password)
end
"""


def test_secret_laundered_rejected():
    assert _mb_codes(LAUNDER_SRC) == ["E0729"], \
        "Secret into a plain-String param erases the marker - must refuse"
    print("E0729: secret laundered through helper rejected")


def test_marked_param_clean():
    src = """
function logIt(msg: Secret<String>) returns Unit
  effects log
do
  print(reveal(msg))
end

function main(password: Secret<String>) returns Unit
  effects log
do
  logIt(password)
end
"""
    assert _mb_codes(src) == [], \
        "a Secret-typed callee param carries the marker - sanctioned"
    print("E0729: marker-typed param passes clean")


def test_revealed_arg_clean():
    src = """
function logIt(msg: String) returns Unit
  effects log
do
  print(msg)
end

function main(password: Secret<String>) returns Unit
  effects log
do
  logIt(reveal(password))
end
"""
    assert _mb_codes(src) == [], "reveal() at the call site is sanctioned"
    print("E0729: reveal() at boundary passes clean")


def test_untrusted_laundered_rejected():
    src = """
function render(s: String) returns Unit
  effects log
do
  print(s)
end

function main(form: Untrusted<String>) returns Unit
  effects log
do
  render(form)
end
"""
    assert _mb_codes(src) == ["E0729"], \
        "Untrusted into a plain param blinds every sink check downstream"
    print("E0729: untrusted laundered through helper rejected")


def test_pii_source_call_laundered_rejected():
    src = """
function fetchEmail() returns PII<String>
  effects pure
do
  return classifyPII("alice@example.com")
end

function send(addr: String) returns Unit
  effects log
do
  print(addr)
end

function main() returns Unit
  effects log
do
  send(fetchEmail())
end
"""
    assert _mb_codes(src) == ["E0729"], \
        "an inline PII-returning call into a plain param is laundering"
    print("E0729: PII source call into plain param rejected")


def test_stdlib_callee_not_flagged():
    src = """
function main(password: Secret<String>) returns Unit
  effects log
do
  let _t: String = trim(password)
  print("done")
end
"""
    assert _mb_codes(src) == [], \
        "stdlib callees are out of E0729 v1 scope (recorded residual)"
    print("E0729: stdlib callee skipped (v1 scope)")


# --- E0730 return laundering: tainted value under a plain return type ---
# The dual of E0729 closes the signature loop: seeding trusts declared
# return types, so a body that RETURNS a marker-carrying value under a
# plain declared type must be refused - otherwise the signature lies.

def _rl_codes(src: str):
    ast = parse(src, "<rl>")
    return [d.code for d in check_return_laundering(ast)]


RETURN_LAUNDER_SRC = """
function leak(pw: Secret<String>) returns String
  effects pure
do
  return pw
end
"""


def test_secret_return_laundered_rejected():
    assert _rl_codes(RETURN_LAUNDER_SRC) == ["E0730"], \
        "returning a Secret under a plain String return type washes the marker"
    print("E0730: secret returned under plain type rejected")


def test_marker_return_type_clean():
    src = """
function getToken() returns Secret<String>
  effects pure
do
  return classify("tok_live_secret")
end
"""
    assert _rl_codes(src) == [], \
        "a marker-typed return declaration is the honest signature"
    print("E0730: marker-typed return declaration passes clean")


def test_revealed_return_clean():
    src = """
function audit(pw: Secret<String>) returns String
  effects pure
do
  return reveal(pw)
end
"""
    assert _rl_codes(src) == [], "reveal() at the return site is sanctioned"
    print("E0730: reveal() at return passes clean")


def test_untrusted_return_laundered_rejected():
    src = """
function passthru(q: Untrusted<String>) returns String
  effects pure
do
  return q
end
"""
    assert _rl_codes(src) == ["E0730"], \
        "returning an Untrusted under a plain type washes the danger flag"
    print("E0730: untrusted returned under plain type rejected")


def test_source_call_return_laundered_rejected():
    src = """
function mint() returns String
  effects pure
do
  return classify("tok_live_secret")
end
"""
    assert _rl_codes(src) == ["E0730"], \
        "a source-call result returned under a plain type is laundering"
    print("E0730: source call returned under plain type rejected")


def test_plain_return_clean():
    src = """
function greet(name: String) returns String
  effects pure
do
  return "hello " + name
end
"""
    assert _rl_codes(src) == [], "no marker involved - clean"
    print("E0730: plain function passes clean")


def test_unit_function_clean():
    src = """
function emitAudit(pw: Secret<String>) returns Unit
  effects log
do
  print(reveal(pw))
end
"""
    assert _rl_codes(src) == [], "no value-carrying return - nothing to launder"
    print("E0730: Unit function passes clean")


# --- Iter 41: taint through match-arm destructuring ----------------------
# A binding introduced by a match pattern over a tainted scrutinee must
# be tainted. Pre-fix this was a FALSE ACCEPT (the contract-breach
# class): case Some(v) do print(v) leaked a wrapped Secret at exit 0.

MATCH_LEAK_SRC = """
function f(pw: Secret<String>) returns Unit
  effects log
do
  let o: Option<Secret<String>> = Some(pw)
  match o do
    case Some(v) do
      print(v)
    end
    case None() do
      print("none")
    end
  end
end
"""


def test_match_destructured_secret_rejected():
    assert _sec_codes(MATCH_LEAK_SRC) == ["E0712"], \
        "a binding destructured from a tainted scrutinee must be tainted"
    print("E0712: match-destructured secret rejected")


def test_match_destructured_untrusted_rejected():
    src = """
function f(q: Untrusted<String>) returns Unit
  effects log
do
  let o: Option<Untrusted<String>> = Some(q)
  match o do
    case Some(v) do
      print(v)
    end
    case None() do
      print("none")
    end
  end
end
"""
    assert _li_codes(src) == ["E0724"], \
        "untrusted destructured from a tainted Option must stay untrusted"
    print("E0724: match-destructured untrusted rejected")


def test_match_clean_scrutinee_clean():
    src = """
function f() returns Unit
  effects log
do
  let o: Option<String> = Some("plain")
  match o do
    case Some(v) do
      print(v)
    end
    case None() do
      print("none")
    end
  end
end
"""
    assert _sec_codes(src) == [] and _li_codes(src) == [], \
        "destructuring an untainted scrutinee must not taint the binding"
    print("E0712/E0724: clean scrutinee destructure passes clean")


def test_match_revealed_arm_clean():
    src = """
function f(pw: Secret<String>) returns Unit
  effects log
do
  let o: Option<Secret<String>> = Some(pw)
  match o do
    case Some(v) do
      print(reveal(v))
    end
    case None() do
      print("none")
    end
  end
end
"""
    assert _sec_codes(src) == [], \
        "reveal() of the destructured binding is the sanctioned exit"
    print("E0712: reveal() of destructured binding passes clean")


def test_match_destructured_return_laundered_rejected():
    src = """
function f(pw: Secret<String>) returns String
  effects pure
do
  let o: Option<Secret<String>> = Some(pw)
  match o do
    case Some(v) do
      return v
    end
    case None() do
      return "none"
    end
  end
end
"""
    assert _rl_codes(src) == ["E0730"], \
        "returning a destructured tainted binding under a plain type launders"
    print("E0730: match-destructured return laundering rejected")


# --- Iter 42: function-alias laundering (gaps E / E2) --------------------
# `let f = logIt; f(password)` bypassed E0729's callee lookup, and
# `let f = getToken; f()` defeated return-type seeding - both false
# accepts. Aliases are resolved conservatively: flag-more only; an
# aliased unwrapper (let r = reveal) is deliberately NOT honored.

FN_ALIAS_LAUNDER_SRC = """
function logIt(msg: String) returns Unit
  effects log
do
  print(msg)
end

function main(password: Secret<String>) returns Unit
  effects log
do
  let f = logIt
  f(password)
end
"""


def test_fn_alias_launder_rejected():
    assert _mb_codes(FN_ALIAS_LAUNDER_SRC) == ["E0729"], \
        "an aliased callee with a plain param must still refuse the marker"
    print("E0729: function-alias laundering rejected")


def test_fn_alias_chain_rejected():
    src = """
function logIt(msg: String) returns Unit
  effects log
do
  print(msg)
end

function main(password: Secret<String>) returns Unit
  effects log
do
  let f = logIt
  let g = f
  g(password)
end
"""
    assert _mb_codes(src) == ["E0729"], \
        "alias chains (let g = f) must resolve to the target function"
    print("E0729: alias chain rejected")


def test_fn_alias_marked_param_clean():
    src = """
function logIt(msg: Secret<String>) returns Unit
  effects log
do
  print(reveal(msg))
end

function main(password: Secret<String>) returns Unit
  effects log
do
  let f = logIt
  f(password)
end
"""
    assert _mb_codes(src) == [], \
        "single-target alias of a marker-param fn is the sanctioned crossing"
    print("E0729: alias of marker-param fn passes clean")


def test_source_alias_seeding_rejected():
    src = """
function getToken() returns Secret<String>
  effects pure
do
  return classify("tok_live_secret")
end

function main() returns Unit
  effects log
do
  let f = getToken
  let t: Secret<String> = f()
  print(t)
end
"""
    assert _sec_codes(src) == ["E0712"], \
        "a source call through an alias must still seed taint"
    print("E0712: source-alias seeding rejected")


def test_fn_alias_clean_arg_clean():
    src = """
function logIt(msg: String) returns Unit
  effects log
do
  print(msg)
end

function main(password: Secret<String>) returns Unit
  effects log
do
  let f = logIt
  f("static text")
end
"""
    assert _mb_codes(src) == [], "an alias call with a clean arg is fine"
    print("E0729: alias call with clean arg passes clean")


def test_unwrap_alias_not_honored():
    # Deliberate over-flag: an aliased reveal does NOT clear taint - the
    # sanctioned exits are recognized by name at the call site only.
    src = """
function main(pw: Secret<String>) returns Unit
  effects log
do
  let r = reveal
  print(r(pw))
end
"""
    assert _sec_codes(src) == ["E0712"], \
        "aliasing an unwrapper must NOT clear taint (over-flag by design)"
    print("E0712: aliased unwrapper still flagged (documented over-flag)")


# --- BUG-013: `var` bindings and `x = ...` assignments are bindings ----
# The parser emits `Var` (name) and `Assign` (target, no name). Every
# walker that reasons about what a name holds must see all three kinds;
# each of these shapes was exit 0 before the shared `_walk_binds`.

def _fn(body: str, params: str = "password: Secret<String>",
        effects: str = "log") -> str:
    return (f"function main({params}) returns Unit\n  effects {effects}\ndo\n"
            f"{body}\nend\n")


def test_var_bound_secret_rejected():
    assert _sec_codes(_fn("  var x: String = password\n  print(x)")) == ["E0712"]
    assert _sec_codes(_fn("  var y = password\n  print(y)")) == ["E0712"]
    print("E0712: var-bound secret rejected (BUG-013)")


def test_assign_after_literal_tainted():
    src = _fn('  var x: String = ""\n  x = password\n  print(x)')
    assert _sec_codes(src) == ["E0712"], "an assignment is a binding"
    print("E0712: assignment re-taints a literal-initialised var (BUG-013)")


def test_assign_inside_loop_tainted():
    src = _fn('  var i: Int = 0\n  var acc: String = ""\n'
              '  while i < 1 do\n    acc = pw\n    i = i + 1\n  end\n  print(acc)',
              params="pw: Secret<String>")
    assert _sec_codes(src) == ["E0712"]
    print("E0712: assignment inside a loop tainted (BUG-013)")


def test_reassigned_literal_path_unsafe():
    src = """
function readIt(userPath: String) returns Unit
  effects fs.read
do
  let p: String = "/etc/motd"
  p = userPath
  let _r: Result<String, String> = readFile(p)
end
"""
    assert _fs_codes(src) == ["E0711"], "a re-assigned name is not a fixed literal"
    print("E0711: literal-then-reassigned path rejected (BUG-013)")


def test_reassigned_literal_query_unsafe():
    src = """
function q(input: String) returns String
  effects db.query
do
  let s: String = "SELECT 1"
  s = input
  return sqlQuery(s)
end
"""
    assert _sql_codes(src) == ["E0713"]
    print("E0713: literal-then-reassigned query rejected (BUG-013)")


def test_var_literal_never_proven_safe():
    # Direction pin: a `var`-bound literal was never in the safe set
    # (invisible) and still is not — a mutable name is not a fixed literal.
    src = """
function q() returns String
  effects db.query
do
  var s: String = "SELECT 1"
  return sqlQuery(s)
end
"""
    assert _sql_codes(src) == ["E0713"]
    print("E0713: var-bound literal stays refused (flag-more kept)")


def test_var_rebound_resource_id_rejected():
    src = """
function updateDoc(requestedId: String, victimId: String, user: String) returns Unit
  effects db.exec
do
  var docId: String = requestedId
  let proof: Authorized<String> = authorizeResource(user, "docs:edit", docId)
  docId = victimId
  let _r: String = sqlByOwner("UPDATE docs SET b='x' WHERE id = ?", docId, proof)
end
"""
    assert _idor_codes(src) == ["E0717"], "a var declaration counts as a binding"
    print("E0717: var-declared id rebound between guard and sink rejected (BUG-013)")


def test_var_proof_bound_once_accepted():
    # `var` bound exactly once denotes one value, like `let` — the same
    # rule E0716 already applies (test_var_bound_authorize_clean).
    src = """
function updateDoc(docId: String, user: String) returns Unit
  effects db.exec
do
  var proof: Authorized<String> = authorizeResource(user, "docs:edit", docId)
  let _r: String = sqlByOwner("UPDATE docs SET b='x' WHERE id = ?", docId, proof)
end
"""
    assert _idor_codes(src) == []
    print("E0717: var-bound proof on the same id, bound once, accepted")


# --- BUG-014: `for` variables and match-EXPRESSION arms carry taint ---

def test_for_loop_over_marked_list_rejected():
    src = _fn("  for s in secrets do\n    print(s)\n  end",
              params="secrets: List<Secret<String>>")
    assert _sec_codes(src) == ["E0712"]
    src = _fn('  for e in emails do\n    let line: String = "e=" + e\n    print(line)\n  end',
              params="emails: List<PII<String>>")
    assert _pii_codes(src) == ["E0715"]
    print("E0712/E0715: for-loop variable over a marked list rejected (BUG-014)")


def test_for_loop_over_plain_list_clean():
    src = _fn("  for s in names do\n    print(s)\n  end", params="names: List<String>")
    assert _sec_codes(src) == []
    print("E0712: for-loop over a plain list passes clean")


def test_match_expr_arm_secret_rejected():
    src = _fn('  let _r: Unit = match o do\n    case Some(v) do print(v) end\n'
              '    case None() do print("none") end\n  end',
              params="o: Option<Secret<String>>")
    assert _sec_codes(src) == ["E0712"], "match-expression arms bind like match statements"
    print("E0712: match-expression arm over a secret scrutinee rejected (BUG-014)")


# --- BUG-015: an alias of a stdlib sink IS the sink -------------------

def test_sink_alias_sql_rejected():
    src = """
function q(input: String) returns String
  effects db.query
do
  let run = sqlQuery
  return run(input)
end
"""
    assert _sql_codes(src) == ["E0713"]
    print("E0713: aliased sqlQuery rejected (BUG-015)")


def test_sink_alias_path_rejected():
    src = """
function w(userPath: String) returns Unit
  effects fs.write
do
  let wr = writeFile
  let _r: Result<Unit, String> = wr(userPath, "x")
end
"""
    assert _fs_codes(src) == ["E0711"]
    print("E0711: aliased writeFile rejected (BUG-015)")


def test_sink_alias_print_secret_rejected():
    assert _sec_codes(_fn("  let out = print\n  out(password)")) == ["E0712"]
    print("E0712: aliased print rejected (BUG-015)")


def test_sink_alias_effect_rejected():
    src = """
function pureButExecs() returns String
  effects pure
do
  let sh = shellExec
  return sh("ls")
end
"""
    codes = [d.code for d in check_effects(parse(src, "<alias>"))]
    assert codes == ["E0801"], "an aliased effectful stdlib call needs the effect"
    print("E0801: aliased shellExec under `effects pure` rejected (BUG-015)")


def test_sink_alias_capability_rejected():
    src = """
module M
  requires capability log
end
function run() returns String
  effects exec.run
do
  let sh = shellExec
  return sh("ls")
end
"""
    codes = [d.code for d in check_capabilities(parse(src, "<alias>"))]
    assert codes == ["E0701"], "the call graph must follow the alias"
    print("E0701: aliased shellExec reaches the capability check (BUG-015)")


def test_sink_alias_mutation_needs_proof():
    src = """
function cancel(orderId: String) returns Unit
  effects db.exec
do
  let ex = sqlExec
  let _r: String = ex(sqlBind("UPDATE o SET s='c' WHERE id = ?", orderId))
end
"""
    assert _authz_codes(src) == ["E0716"]
    print("E0716: aliased sqlExec still needs an authorization proof (BUG-015)")


def test_sink_alias_resource_needs_bound_proof():
    src = """
function updateDoc(requestedId: String, victimId: String, user: String) returns Unit
  effects db.exec
do
  let proof: Authorized<String> = authorizeResource(user, "docs:edit", requestedId)
  let owner = sqlByOwner
  let _r: String = owner("UPDATE docs SET b='x' WHERE id = ?", victimId, proof)
end
"""
    assert _idor_codes(src) == ["E0717"]
    print("E0717: aliased sqlByOwner still needs a same-id proof (BUG-015)")


# --- BUG-016: a record with a marked field CARRIES the marker ---------

REC = """
record User do
  email: PII<String>
  name: String
end
"""


def test_whole_record_at_sink_rejected():
    src = REC + """
function report(u: User) returns Unit
  effects log, fs.write
do
  print(u)
  let _r: Result<Unit, String> = writeFile("/var/log/u.log", u)
end
"""
    assert _pii_codes(src) == ["E0715", "E0715"], "the record carries the PII field"
    print("E0715: whole record into print/writeFile rejected (BUG-016)")


def test_constructed_record_at_sink_rejected():
    src = REC + """
function report2(e: PII<String>) returns Unit
  effects log
do
  let r: User = User(e, "jane")
  print(r)
end
"""
    assert _pii_codes(src) == ["E0715"]
    print("E0715: freshly constructed record into print rejected (BUG-016)")


def test_plain_field_of_record_clean():
    # Reading the UNMARKED field of a record-typed name is not a leak —
    # example 28's `print("user=" + u.name)` must stay clean, also through
    # a bare alias of the record and a record-returning call.
    src = REC + """
function build(e: PII<String>) returns User
  effects pure
do
  return User(e, "jane")
end
function report(u: User) returns Unit
  effects log
do
  print("user=" + u.name)
  let r = u
  print(r.name)
  let b = build(classifyPII("x"))
  print(b.name)
end
"""
    assert _pii_codes(src) == []
    print("E0715: plain field of a carrier record passes clean")


def test_marked_field_of_record_still_rejected():
    src = REC + """
function report(u: User) returns Unit
  effects log
do
  print(u.email)
end
"""
    assert _pii_codes(src) == ["E0715"]
    print("E0715: marked field of a carrier record still rejected")


def test_secret_wrapped_record_field_still_rejected():
    # The prune is for a name whose TYPE is the record; under Secret<User>
    # every field is secret, so `s.name` leaks.
    src = """
record Acct do
  name: String
end
function f(s: Secret<Acct>) returns Unit
  effects log
do
  print(s.name)
end
"""
    assert _sec_codes(src) == ["E0712"]
    print("E0712: field read through Secret<Record> still rejected")


def test_record_param_crossing_sanctioned():
    src = REC + """
function helper(x: User) returns Unit
  effects log
do
  print(x.name)
end
function report(u: User) returns Unit
  effects log
do
  helper(u)
end
"""
    assert _mb_codes(src) == [], "a record-typed param carries the marker"
    print("E0729: record into a record-typed param passes clean")


def test_record_into_plain_param_rejected():
    src = REC + """
function helper(x: String) returns Unit
  effects log
do
  print(x)
end
function report(u: User) returns Unit
  effects log
do
  helper(u)
end
"""
    assert _mb_codes(src) == ["E0729"]
    print("E0729: record into a plain param rejected (BUG-016)")


def test_record_returned_under_plain_type_rejected():
    src = REC + """
function leak(u: User) returns String
  effects pure
do
  return u
end
function honest(u: User) returns User
  effects pure
do
  return u
end
"""
    assert _rl_codes(src) == ["E0730"], "only the plain-typed return launders"
    print("E0730: record returned under a plain type rejected (BUG-016)")


# --- AEDET-11/12/13: one URL-authority parser for E0710/E0721/E0722 ----

def test_authority_wildcards_inside_host_rejected():
    for a in ("https://*.*/*", "https://api.*/*", "https://trusted.example@*/*",
              "https://a*/*", "https://api.example.com*/*", "https://[*]/*",
              "https://*.com/*", "https://api.*.example.com/*"):
        assert _net_authority_wildcarded(a) is not None, f"should flag: {a!r}"
    for a in ("https://*.example.com:443/*", "https://user@api.example.com/*"):
        assert _net_authority_wildcarded(a) is None, f"should allow: {a!r}"
    print("E0710: wildcards inside the host/authority flagged")


def _scope(url: str) -> str:
    return f'function f() returns String\n  effects net.fetch("{url}")\ndo\n  return "x"\nend\n'


def test_loopback_spellings():
    for url in ("http://127.0.0.1.evil.com/*", "http://127.0.0.1@evil.com/*",
                "http://localhost@evil.com/*", "http://127.0.0.1.nip.io/*",
                "http://2130706433/*"):     # an obfuscated spelling is not a sanctioned loopback
        assert _ct_codes(_scope(url)) == ["E0721"], f"should flag: {url!r}"
    for url in ("http://[::1]/*", "http://[::1]:8080/*", "http://[::ffff:127.0.0.1]/*",
                "http://evil.com@127.0.0.1/*", "http://LOCALHOST/*", "http://0.0.0.0/*"):
        assert _ct_codes(_scope(url)) == [], f"should allow: {url!r}"
    print("E0721: loopback exemption is host-exact (userinfo, brackets, suffixes handled)")


def test_metadata_spellings_rejected():
    for url in ("https://[fd00:ec2::254]/*", "https://fd00:ec2::254/*",
                "https://metadata.google.internal/*", "https://metadata/*",
                "https://instance-data/*", "https://100.100.100.200/*",
                "https://2852039166/*", "https://0xa9fea9fe/*",
                "https://0251.0376.0251.0376/*", "https://0xA9.0xFE.0xA9.0xFE/*",
                "https://169.254.43518/*", "https://user@169.254.169.254/*",
                "https://[::ffff:169.254.169.254]/*", "https://[::ffff:a9fe:a9fe]/*",
                "https://169.254.169.254.nip.io/*", "169.254.169.254/*"):
        assert _md_codes(_scope(url)) == ["E0722"], f"should flag: {url!r}"
    for url in ("https://10.0.0.1/*", "https://0x10.0.0.1/*", "https://api.metadata.example/*"):
        assert _md_codes(_scope(url)) == [], f"should allow: {url!r}"
    print("E0722: IPv6/DNS/decimal/hex/octal/userinfo metadata spellings rejected")


# --- AEDET-14/15: E0723 provider shapes, PEM body, literal position ----

PROVIDER_TOKENS = (
    "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
    "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL",
    "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-abcdefAA",
    "hf_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
    "gsk_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV",
    "ya29.a0AfH6SMBabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "glpat-abcdefghijklmnopqrst",
    "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
    "npm_abcdefghijklmnopqrstuvwxyz0123456789",
    "pypi-AgEIcHlwaS5vcmcCJGFiY2RlZmdoLWlqa2wtbW5vcC1xcnN0LXV2d3h5ejEyMzQ1NgACKlszLCJmZTY0",
    "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
)


def _lit(s: str) -> str:
    return f'function k() returns String\n  effects pure\ndo\n  return "{s}"\nend\n'


def test_provider_tokens_rejected():
    for tok in PROVIDER_TOKENS:
        assert _hc_codes(_lit(tok)) == ["E0723"], f"should flag: {tok[:16]}..."
    for s in ("sk-short", "hf_short", "gsk_x", "glpat-short", "npm_short", "SG.a.b",
              "ask-" + "a" * 48, "sk-proj-tooshort"):
        assert _hc_codes(_lit(s)) == [], f"should allow: {s!r}"
    print(f"E0723: {len(PROVIDER_TOKENS)} provider token shapes rejected, short look-alikes clean")


def test_pem_needs_a_body():
    header_only = _lit("expected a -----BEGIN RSA PRIVATE KEY----- block")
    assert _hc_codes(header_only) == [], "a PEM header in prose is not a key"
    body = ("-----BEGIN RSA PRIVATE KEY-----\\n"
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHiM6ZbLe8h0aQ9wVxa7\\n"
            "-----END RSA PRIVATE KEY-----")
    assert _hc_codes(_lit(body)) == ["E0723"], "a PEM header with a base64 body is a key"
    print("E0723: PEM header alone clean, header + body rejected")


def test_hardcoded_secret_positioned():
    src = 'function k() returns String\n  effects pure\ndo\n  return "AKIAIOSFODNN7EXAMPLE"\nend\n'
    d = check_hardcoded_secret(parse(src, "<pos>"))[0]
    assert (d.position.line, d.position.column) == (4, 10), \
        f"E0723 must anchor on the literal, got {d.position}"
    print("E0723: reported at the string literal's line and column")


# --- AEDET-18: E0207 over Int treats open bounds as integers -----------

def test_int_open_bounds_rejected():
    ref = lambda s: [d.code for d in check_unsatisfiable_refinement(parse(s, "<ref>"))]
    assert ref("type Bad = Int where self > 5 and self < 6") == ["E0207"], \
        "no integer lies strictly between 5 and 6"
    assert ref("type Ok = Int where self > 5 and self < 7") == []
    assert ref("type Real = Float where self > 5.0 and self < 6.0") == [], \
        "a real interval (5, 6) is inhabited"
    print("E0207: adjacent open Int bounds rejected, Float and inhabited Int clean")


# --- E0731 code injection (CWE-94/95) ------------------------------------
# `evalCode(source)` runs source text. Like E0719 it is literal-only with
# `trusted(...)` as the sole exit: there is no sanitizer for attacker-
# authored code.

def _code_codes(src: str):
    ast = parse(src, "<code>")
    return [d.code for d in check_code_injection(ast)]


def _ec(expr: str) -> str:
    return f"""
function run(userInput: String) returns String
  effects pure
do
  return evalCode({expr})
end
"""


def test_code_concat_rejected():
    assert _code_codes(_ec('"print(1); " + userInput')) == ["E0731"], \
        "source built by concatenation must raise E0731"
    print("E0731: concatenated source rejected")


def test_code_param_rejected():
    assert _code_codes(_ec("userInput")) == ["E0731"], \
        "bare-parameter source must raise E0731"
    print("E0731: parameter-as-source rejected")


def test_code_call_rejected():
    assert _code_codes(_ec("trim(userInput)")) == ["E0731"], \
        "a computed source must raise E0731"
    print("E0731: computed source rejected")


def test_code_literal_clean():
    assert _code_codes(_ec('"print(1)"')) == [], "a fixed literal source is safe"
    print("E0731: literal source passes clean")


def test_code_literal_binding_clean():
    src = """
function run() returns String
  effects pure
do
  let s: String = "print(1)"
  return evalCode(s)
end
"""
    assert _code_codes(src) == [], "source bound to a literal is safe"
    print("E0731: literal-bound source passes clean")


def test_code_trusted_clean():
    src = """
function run(bundle: String) returns String
  effects pure
do
  return evalCode(trusted(bundle))
end
"""
    assert _code_codes(src) == [], "trusted(...) is the explicit trust boundary"
    print("E0731: trusted(...) source passes clean")


# --- BUG-020: a wrapper's PINNING argument is judged too ------------------

def test_wrapper_pinning_argument_rejected():
    sql = """
function q(tmpl: String, v: String) returns String
  effects db.query
do
  return sqlQuery(sqlBind(tmpl, v))
end
"""
    assert [d.code for d in check_injection(parse(sql, "<p>"))] == ["E0713"], \
        "sqlBind with a parameter template launders the query text"
    sh = """
function run(tmpl: String, v: String) returns String
  effects exec.run
do
  return shellExec(shellArg(tmpl, v))
end
"""
    assert [d.code for d in check_command_injection(parse(sh, "<p>"))] == ["E0714"]
    rd = """
function go(host: String, p: String) returns String
  effects net.redirect
do
  return redirect(safeRedirect(host, p))
end
"""
    assert [d.code for d in check_open_redirect(parse(rd, "<p>"))] == ["E0718"]
    print("E0713/E0714/E0718: a wrapper's template/host must itself be pinned (BUG-020)")


def test_wrapper_literal_pin_clean():
    sql = """
function q(v: String) returns String
  effects db.query
do
  return sqlQuery(sqlBind("SELECT * FROM t WHERE id = ?", v))
end
"""
    assert [d.code for d in check_injection(parse(sql, "<p>"))] == []
    fs = """
function w(base: String, name: String) returns Unit
  effects fs.write
do
  let _r: Result<Unit, String> = writeFile(safeJoin(base, name), "x")
end
"""
    # safeJoin's base is deliberately NOT pinned: a base directory handed
    # in as a parameter is the idiom, and the untrusted half is `name`.
    assert [d.code for d in check_fs_path_safety(parse(fs, "<p>"))] == []
    print("E0713/E0711: literal template clean; safeJoin base stays unpinned")


if __name__ == "__main__":
    test_authority_predicate()
    test_broad_rejected()
    test_scheme_only_rejected()
    test_pinned_clean()
    test_subdomain_pin_clean()
    test_mixed_arg_effect_list_does_not_crash()
    test_fs_dynamic_path_rejected()
    test_fs_literal_clean()
    test_fs_literal_dotdot_rejected()
    test_fs_safejoin_clean()
    test_fs_readfile_covered()
    test_secret_logged_rejected()
    test_secret_revealed_clean()
    test_secret_persisted_to_disk_rejected()
    test_secret_disk_path_arg_not_flagged()
    test_secret_taint_propagates()
    test_nonsecret_clean()
    test_sql_concat_rejected()
    test_sql_bind_clean()
    test_sql_literal_clean()
    test_sql_bind_via_binding_clean()
    test_shell_concat_rejected()
    test_shell_arg_clean()
    test_shell_literal_clean()
    test_shell_arg_via_binding_clean()
    test_pii_logged_rejected()
    test_pii_persisted_rejected()
    test_pii_redacted_clean()
    test_pii_path_arg_not_flagged()
    test_mutation_without_auth_rejected()
    test_unproven_auth_token_rejected()
    test_direct_authorize_clean()
    test_authorize_via_binding_clean()
    test_authorized_param_clean()
    test_launder_via_authorized_param_rejected()
    test_assign_demotes_authorized_binding()
    test_var_bound_authorize_clean()
    test_annotation_cannot_mint_authorized()
    test_authorize_resource_is_a_proof_for_e0716()
    test_result_wrapped_proof_via_match_clean()
    test_fake_minter_return_rejected()
    test_match_on_unproven_result_rejected()
    test_gated_function_escape_rejected()
    test_sqlexec_concat_query_rejected_by_injection()
    test_wrong_resource_rejected()
    test_same_resource_direct_clean()
    test_same_resource_via_binding_clean()
    test_same_literal_clean_different_literal_rejected()
    test_rebound_id_rejected()
    test_unbound_proof_rejected()
    test_missing_proof_rejected()
    test_sqlbyowner_concat_stmt_rejected_by_injection()
    test_redirect_dynamic_rejected()
    test_redirect_literal_clean()
    test_redirect_safe_clean()
    test_redirect_safe_via_binding_clean()
    test_template_concat_rejected()
    test_template_param_rejected()
    test_template_literal_clean()
    test_template_literal_binding_clean()
    test_template_trusted_clean()
    test_deserialize_untrusted_rejected()
    test_deserialize_concat_rejected()
    test_schema_decode_clean()
    test_deserialize_literal_clean()
    test_deserialize_trusted_clean()
    test_cleartext_http_rejected()
    test_https_clean()
    test_loopback_http_clean()
    test_metadata_ip_rejected()
    test_link_local_range_rejected()
    test_normal_host_not_metadata()
    test_aws_key_rejected()
    test_github_token_rejected()
    test_demo_password_clean()
    test_env_sourced_clean()
    test_untrusted_logged_rejected()
    test_sanitized_log_clean()
    test_trusted_string_not_flagged()
    test_untrusted_html_rejected()
    test_html_escape_clean()
    test_wrong_sanitizer_still_xss()
    test_untrusted_header_rejected()
    test_sanitize_header_clean()
    test_untrusted_xml_rejected()
    test_parse_xml_safe_clean()
    test_untrusted_csv_rejected()
    test_csv_escape_clean()
    test_detectors_compose_additively()
    test_secret_return_taint_rejected()
    test_secret_inline_source_call_rejected()
    test_secret_return_revealed_clean()
    test_classify_inline_rejected()
    test_pii_return_taint_rejected()
    test_untrusted_return_taint_rejected()
    test_plain_return_still_clean()
    test_list_of_pii_param_tainted()
    test_option_of_secret_param_tainted()
    test_nested_marker_param_crossing_sanctioned()
    test_nested_marker_return_type_clean()
    test_nested_authorized_still_unproven()
    test_record_field_read_tainted()
    test_record_field_read_redacted_clean()
    test_record_field_bound_then_leaked()
    test_plain_record_field_still_clean()
    test_record_construction_is_sanctioned_crossing()
    test_record_return_is_not_laundering()
    test_record_unmarked_field_still_launders()
    test_secret_laundered_rejected()
    test_marked_param_clean()
    test_revealed_arg_clean()
    test_untrusted_laundered_rejected()
    test_pii_source_call_laundered_rejected()
    test_stdlib_callee_not_flagged()
    test_secret_return_laundered_rejected()
    test_marker_return_type_clean()
    test_revealed_return_clean()
    test_untrusted_return_laundered_rejected()
    test_source_call_return_laundered_rejected()
    test_plain_return_clean()
    test_unit_function_clean()
    test_match_destructured_secret_rejected()
    test_match_destructured_untrusted_rejected()
    test_match_clean_scrutinee_clean()
    test_match_revealed_arm_clean()
    test_match_destructured_return_laundered_rejected()
    test_fn_alias_launder_rejected()
    test_fn_alias_chain_rejected()
    test_fn_alias_marked_param_clean()
    test_source_alias_seeding_rejected()
    test_fn_alias_clean_arg_clean()
    test_unwrap_alias_not_honored()
    test_var_bound_secret_rejected()
    test_assign_after_literal_tainted()
    test_assign_inside_loop_tainted()
    test_reassigned_literal_path_unsafe()
    test_reassigned_literal_query_unsafe()
    test_var_literal_never_proven_safe()
    test_var_rebound_resource_id_rejected()
    test_var_proof_bound_once_accepted()
    test_for_loop_over_marked_list_rejected()
    test_for_loop_over_plain_list_clean()
    test_match_expr_arm_secret_rejected()
    test_sink_alias_sql_rejected()
    test_sink_alias_path_rejected()
    test_sink_alias_print_secret_rejected()
    test_sink_alias_effect_rejected()
    test_sink_alias_capability_rejected()
    test_sink_alias_mutation_needs_proof()
    test_sink_alias_resource_needs_bound_proof()
    test_whole_record_at_sink_rejected()
    test_constructed_record_at_sink_rejected()
    test_plain_field_of_record_clean()
    test_marked_field_of_record_still_rejected()
    test_secret_wrapped_record_field_still_rejected()
    test_record_param_crossing_sanctioned()
    test_record_into_plain_param_rejected()
    test_record_returned_under_plain_type_rejected()
    test_authority_wildcards_inside_host_rejected()
    test_loopback_spellings()
    test_metadata_spellings_rejected()
    test_provider_tokens_rejected()
    test_pem_needs_a_body()
    test_hardcoded_secret_positioned()
    test_int_open_bounds_rejected()
    test_code_concat_rejected()
    test_code_param_rejected()
    test_code_call_rejected()
    test_code_literal_clean()
    test_code_literal_binding_clean()
    test_code_trusted_clean()
    test_wrapper_pinning_argument_rejected()
    test_wrapper_literal_pin_clean()
    print("E0710..E0731 ALL REACH-SCOPE TESTS PASS")
