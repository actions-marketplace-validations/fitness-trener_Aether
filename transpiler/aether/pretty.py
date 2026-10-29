"""C.1 canonical pretty-printer.

Takes a parsed AST (the dict shape produced by `aether.parser.parse`)
and emits Aether source. The contract is the round-trip property:

    parse(pretty(parse(src))) == parse(src)   # modulo position metadata

The pretty-printer aggressively parenthesises binary expressions and
emits effect args verbatim from their stored form. It does not
preserve original whitespace. Given the source (`pretty(ast, source)`),
it keeps full-line `//` comments above declarations and statements —
including a `// expect:` header; what is still lost is listed on
`pretty`.

Public API:
    pretty(ast, source=None) -> str
    pretty_normalized(src) -> str          # convenience: parse + pretty
    asts_equal_ignoring_pos(a, b) -> bool   # round-trip oracle
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional


# ----------------------------------------------------------------------
# Top-level entry points
# ----------------------------------------------------------------------

def pretty(ast: Dict[str, Any], source: Optional[str] = None) -> str:
    """Render `ast`. Pass the `source` it was parsed from to keep that
    source's full-line `//` comments: each run of comment lines is
    re-attached above the declaration or statement that followed it, and
    the run after the last declaration is kept at the end. That covers
    the leading block (so a `// expect:` header survives `fmt --write` and
    the fix-loop), comments between declarations, and comments above a
    statement. Nodes are matched by `pos.line`, so an AST edited in place
    (sdk.edit) keeps them.

    Still lost (documented, not silent): a comment above something that is
    not a declaration or statement (a `case` arm, a clause line, a line
    inside a multi-line expression), a comment right before a block's
    `end`, trailing `code // comment` remarks, and `/* */` blocks. The
    lexer drops comments, so only these line-anchored ones can be
    recovered from the text."""
    p = Pretty(_comment_blocks(source, ast) if source is not None else None)
    p.emit_program(ast)
    return p.render()


def _comment_blocks(source: str, ast: Dict[str, Any]) -> Dict[Any, List[str]]:
    """{node start line: [comment lines above it]}, plus key None for the
    comments after the last code line. A block is the run of `//` and
    blank lines directly above an anchor line, scanning up to the nearest
    code line. Blank runs are collapsed to one line and leading blanks
    dropped, so the output is a fixed point."""
    lines = source.splitlines()
    starts = sorted(_pos_lines(ast, set()))
    out: Dict[Any, List[str]] = {}
    for key, stop in [(s, s - 1) for s in starts] + [(None, len(lines))]:
        i = stop
        while i >= 1 and (not lines[i - 1].strip()
                          or lines[i - 1].lstrip().startswith("//")):
            i -= 1
        block: List[str] = []
        for ln in lines[i:stop]:
            ln = ln.rstrip()
            if ln or (block and block[-1]):
                block.append(ln)
        while block and not block[0]:
            block.pop(0)
        if key is None:
            while block and not block[-1]:
                block.pop()
        if any(block):
            out[key] = block
    return out


def _pos_lines(x: Any, acc: set) -> set:
    """Every `pos.line` in the tree — the lines a comment block can be
    anchored above. Only decls and statements consume their block."""
    if isinstance(x, dict):
        pos = x.get("pos")
        if isinstance(pos, dict) and isinstance(pos.get("line"), int):
            acc.add(pos["line"])
        for v in x.values():
            _pos_lines(v, acc)
    elif isinstance(x, list):
        for v in x:
            _pos_lines(v, acc)
    return acc


def pretty_normalized(src: str) -> str:
    from .parser import parse
    return pretty(parse(src, "<pretty>"))


def asts_equal_ignoring_pos(a: Any, b: Any) -> bool:
    return _strip_pos(a) == _strip_pos(b)


_IGNORED_KEYS = {"pos", "position"}


def _strip_pos(x: Any) -> Any:
    if isinstance(x, dict):
        return {k: _strip_pos(v) for k, v in x.items() if k not in _IGNORED_KEYS}
    if isinstance(x, list):
        return [_strip_pos(v) for v in x]
    return x


# ----------------------------------------------------------------------
# Visitor
# ----------------------------------------------------------------------

class Pretty:
    def __init__(self, comments: Optional[Dict[Any, List[str]]] = None):
        self.lines: List[str] = []
        self.indent_level = 0
        self.comments = comments or {}

    def line(self, s: str = "") -> None:
        self.lines.append("" if s == "" else ("  " * self.indent_level + s))

    def render(self) -> str:
        return "\n".join(self.lines) + ("\n" if self.lines else "")

    def indent(self) -> None: self.indent_level += 1
    def dedent(self) -> None: self.indent_level -= 1

    # --- driver --------------------------------------------------------

    def emit_program(self, n: Dict[str, Any]) -> None:
        for i, d in enumerate(n.get("decls", [])):
            if i > 0:
                self.line("")
            self.emit_comments(d)
            self.emit_decl(d)
        tail = self.comments.get(None)
        if tail:
            if self.lines:
                self.line("")
            self.lines.extend(tail)

    def emit_comments(self, n: Dict[str, Any]) -> None:
        # pop: a statement sharing its line with its parent (`if c then
        # return 1 end`) must not print the same block twice.
        # A node without its own `pos` (ExprStmt) starts at its first
        # positioned child.
        if self.comments:
            lines = _pos_lines(n, set())
            if lines:
                self.lines.extend(self.comments.pop(min(lines), []))

    def emit_decl(self, n: Dict[str, Any]) -> None:
        k = n["kind"]
        m = getattr(self, "emit_" + k, None)
        if m is None:
            raise NotImplementedError(f"pretty: no emit_{k}")
        m(n)

    # --- top-level decls ----------------------------------------------

    def emit_ModuleDecl(self, n: Dict[str, Any]) -> None:
        self.line(f"module {n['name']}")
        self.indent()
        for cap in n.get("capabilities", []):
            self.line(f"requires capability {cap}")
        exports = n.get("exports", [])
        if exports:
            self.line("exports " + ", ".join(exports))
        self.dedent()
        self.line("end")

    def emit_ImportDecl(self, n: Dict[str, Any]) -> None:
        s = "import " + ".".join(n["path"])
        if n.get("alias"):
            s += f" as {n['alias']}"
        self.line(s)

    def emit_TypeDecl(self, n: Dict[str, Any]) -> None:
        head = f"type {n['name']} = " + self.fmt_type(n["base"])
        if n.get("refinement"):
            head += " where " + self.fmt_expr(n["refinement"])
        self.line(head)

    def emit_RecordDecl(self, n: Dict[str, Any]) -> None:
        self.line(f"record {n['name']}")
        self.indent()
        self.line("do")
        self.indent()
        for f in n.get("fields", []):
            self.line(f"{f['name']}: {self.fmt_type(f['type'])}")
        self.dedent()
        self.dedent()
        self.line("end")

    def emit_UnionDecl(self, n: Dict[str, Any]) -> None:
        self.line(f"union {n['name']} do")
        self.indent()
        for ctor in n["cases"]:
            cname = ctor["name"]
            params = ctor.get("params", [])
            if params:
                argstr = ", ".join(f"{p['name']}: {self.fmt_type(p['type'])}" for p in params)
                self.line(f"case {cname}({argstr})")
            else:
                self.line(f"case {cname}")
        self.dedent()
        self.line("end")

    def emit_ConstDecl(self, n: Dict[str, Any]) -> None:
        self.line(f"const {n['name']}: {self.fmt_type(n['type'])} = {self.fmt_expr(n['value'])}")

    def emit_FunctionDecl(self, n: Dict[str, Any]) -> None:
        params = ", ".join(f"{p['name']}: {self.fmt_type(p['type'])}" for p in n.get("params", []))
        head = f"function {n['name']}"
        if n.get("generics"):
            head += "<" + ", ".join(n["generics"]) + ">"
        head += f"({params}) returns {self.fmt_type(n['return_type'])}"
        self.line(head)
        self.indent()
        for clause in n.get("requires", []):
            self.line("requires " + self.fmt_expr(clause))
        for clause in n.get("ensures", []):
            self.line("ensures " + self.fmt_expr(clause))
        effs = n.get("effects", [])
        if effs:
            self.line("effects " + ", ".join(self.fmt_effect(e) for e in effs))
        self.dedent()
        self.line("do")
        self.indent()
        for s in n["body"]:
            self.emit_stmt(s)
        self.dedent()
        self.line("end")

    def fmt_effect(self, e: Dict[str, Any]) -> str:
        s = ".".join(e["path"])
        arg = e.get("arg")
        if arg is not None:
            # The parser stores effect args as full expression nodes
            # (typically a StringLit). Render via fmt_expr so the
            # round-trip is byte-faithful.
            s += "(" + self.fmt_expr(arg) + ")"
        return s

    # --- statements ----------------------------------------------------

    def emit_stmt(self, n: Dict[str, Any]) -> None:
        self.emit_comments(n)
        k = n["kind"]
        m = getattr(self, "emit_stmt_" + k, None)
        if m is None:
            raise NotImplementedError(f"pretty: no emit_stmt_{k}")
        m(n)

    def emit_stmt_Let(self, n: Dict[str, Any]) -> None:
        ty = self.fmt_type(n["type"]) if n.get("type") else None
        rhs = self.fmt_expr(n["value"])
        if ty:
            self.line(f"let {n['name']}: {ty} = {rhs}")
        else:
            self.line(f"let {n['name']} = {rhs}")

    def emit_stmt_Var(self, n: Dict[str, Any]) -> None:
        ty = self.fmt_type(n["type"]) if n.get("type") else None
        rhs = self.fmt_expr(n["value"])
        if ty:
            self.line(f"var {n['name']}: {ty} = {rhs}")
        else:
            self.line(f"var {n['name']} = {rhs}")

    def emit_stmt_Assign(self, n: Dict[str, Any]) -> None:
        # target is a plain ident string in this AST shape
        self.line(f"{n['target']} = {self.fmt_expr(n['value'])}")

    def emit_stmt_ExprStmt(self, n: Dict[str, Any]) -> None:
        self.line(self.fmt_expr(n["expr"]))

    def emit_stmt_Return(self, n: Dict[str, Any]) -> None:
        v = n.get("value")
        if v is None:
            self.line("return")
        else:
            self.line(f"return {self.fmt_expr(v)}")

    def emit_stmt_Break(self, n): self.line("break")
    def emit_stmt_Continue(self, n): self.line("continue")

    def emit_stmt_If(self, n: Dict[str, Any]) -> None:
        self.line(f"if {self.fmt_expr(n['cond'])} then")
        self.indent()
        for s in n["then"]:
            self.emit_stmt(s)
        self.dedent()
        for elif_clause in n.get("elifs", []):
            self.line(f"elif {self.fmt_expr(elif_clause['cond'])} then")
            self.indent()
            for s in elif_clause["body"]:
                self.emit_stmt(s)
            self.dedent()
        else_body = n.get("else")
        if else_body:
            self.line("else")
            self.indent()
            for s in else_body:
                self.emit_stmt(s)
            self.dedent()
        self.line("end")

    def emit_stmt_While(self, n: Dict[str, Any]) -> None:
        self.line(f"while {self.fmt_expr(n['cond'])} do")
        self.indent()
        for s in n["body"]:
            self.emit_stmt(s)
        self.dedent()
        self.line("end")

    def emit_stmt_For(self, n: Dict[str, Any]) -> None:
        self.line(f"for {n['var']} in {self.fmt_expr(n['iter'])} do")
        self.indent()
        for s in n["body"]:
            self.emit_stmt(s)
        self.dedent()
        self.line("end")

    def emit_stmt_Match(self, n: Dict[str, Any]) -> None:
        self.line(f"match {self.fmt_expr(n['scrutinee'])} do")
        self.indent()
        for arm in n["arms"]:
            self.line(f"case {self.fmt_pat(arm['pattern'])} do")
            self.indent()
            for s in arm["body"]:
                self.emit_stmt(s)
            self.dedent()
            self.line("end")
        self.dedent()
        self.line("end")

    # --- expressions (string-valued) ----------------------------------

    def fmt_expr(self, n: Any) -> str:
        if n is None:
            return ""
        k = n["kind"]
        m = getattr(self, "expr_" + k, None)
        if m is None:
            raise NotImplementedError(f"pretty: no expr_{k}")
        return m(n)

    def expr_IntLit(self, n):   return str(n["value"])
    def expr_FloatLit(self, n):
        s = repr(float(n["value"]))
        if "." not in s and "e" not in s and "E" not in s:
            s += ".0"
        return s
    def expr_StringLit(self, n):
        v = n["value"]
        v = v.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{v}"'
    def expr_BoolLit(self, n):  return "true" if n["value"] else "false"
    def expr_NullLit(self, n):  return "null"
    def expr_Ident(self, n):    return n["name"]
    def expr_Old(self, n):      return f"old({self.fmt_expr(n['value'])})"

    def expr_BinOp(self, n):
        return f"({self.fmt_expr(n['left'])} {n['op']} {self.fmt_expr(n['right'])})"

    def expr_UnaryOp(self, n):
        op = n["op"]
        inner = self.fmt_expr(n["value"])
        if op == "neg":
            return f"(-{inner})"
        if op == "not":
            return f"(not {inner})"
        return f"({op} {inner})"

    def expr_Call(self, n):
        args = ", ".join(self.fmt_expr(a) for a in n["args"])
        return f"{self.fmt_expr(n['func'])}({args})"

    def expr_Field(self, n):
        return f"{self.fmt_expr(n['value'])}.{n['name']}"

    def expr_Index(self, n):
        return f"{self.fmt_expr(n['value'])}[{self.fmt_expr(n['index'])}]"

    def expr_ListLit(self, n):
        return "[" + ", ".join(self.fmt_expr(e) for e in n.get("elems", [])) + "]"

    def expr_MapLit(self, n):
        entries = ", ".join(
            f"{self.fmt_expr(e['key'])}: {self.fmt_expr(e['value'])}"
            for e in n.get("entries", [])
        )
        return "{" + entries + "}"

    def expr_IfExpr(self, n):
        parts = [f"if {self.fmt_expr(n['cond'])} then {self.fmt_expr(n['then'])}"]
        for e in n.get("elifs", []):
            parts.append(f"elif {self.fmt_expr(e['cond'])} then {self.fmt_expr(e['value'])}")
        parts.append(f"else {self.fmt_expr(n['else'])} end")
        return " ".join(parts)

    def expr_MatchExpr(self, n):
        out = [f"match {self.fmt_expr(n['scrutinee'])} do"]
        for arm in n["arms"]:
            out.append(f"case {self.fmt_pat(arm['pattern'])} do {self.fmt_expr(arm['value'])} end")
        out.append("end")
        return " ".join(out)

    # --- patterns ------------------------------------------------------

    def fmt_pat(self, n: Dict[str, Any]) -> str:
        k = n["kind"]
        if k == "WildcardPat":
            return "_"
        if k == "LiteralPat":
            lk = n.get("lit_kind")
            v = n["value"]
            if lk == "string":
                return '"' + str(v).replace('\\', '\\\\').replace('"', '\\"') + '"'
            if lk == "kw":
                return str(v)  # true / false / null
            return str(v)
        if k == "BindPat":
            return n["name"]
        if k == "ConstructorPat":
            head = ".".join(n["path"])
            args = n.get("args", [])
            if not args:
                return f"{head}()"
            return f"{head}(" + ", ".join(self.fmt_pat(a) for a in args) + ")"
        if k == "AsPat":
            return f"{self.fmt_pat(n['pattern'])} as {n['name']}"
        raise NotImplementedError(f"pretty: no pattern handler for {k}")

    # --- types ---------------------------------------------------------

    def fmt_type(self, n: Optional[Dict[str, Any]]) -> str:
        if n is None:
            return "Unit"
        k = n["kind"]
        if k == "TypeName":
            return n["name"]
        if k == "GenericType":
            return f"{n['name']}<" + ", ".join(self.fmt_type(t) for t in n.get("args", [])) + ">"
        if k == "FunctionType":
            # The parser's keys are `params`/`returns` (parser.py
            # parse_type_expr); this read `args`/`ret` and crashed on every
            # function type (audit 2026-09-24 A9).
            params = ", ".join(self.fmt_type(t) for t in n.get("params", []))
            return f"function({params}) returns {self.fmt_type(n['returns'])}"
        raise NotImplementedError(f"pretty: no type handler for {k}")
