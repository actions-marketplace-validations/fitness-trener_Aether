"""Aether parser. Hand-written recursive descent + Pratt loop for expressions.

Produces a canonical AST as nested Python dicts. The dict shape is documented
in transpiler/aether/ast_schema.json.

The parser tries to recover at statement boundaries when a syntax error is hit;
v0.1 just stops on first error to keep behavior predictable.
"""

from __future__ import annotations
from typing import List, Optional, Dict, Any, Callable

from .lexer import Token, tokenize
from .diagnostics import AetherError, Diagnostic, Position


def parse(source: str, filename: str = "<input>") -> Dict[str, Any]:
    """Strict parse: raises AetherError on the first parse error.

    Backward-compatible single-error API used by the runtime, emitter,
    benchmark harness, and every Phase-A/B regression test.
    """
    tokens = tokenize(source, filename)
    p = Parser(tokens)
    return p.parse_program()


def parse_collect(source: str, filename: str = "<input>"):
    """Lenient parse (C.6): recovers at top-level boundaries and returns
    (ast_or_none, [Diagnostic, ...]).

    - If `diagnostics` is empty, `ast_or_none` is a well-formed program.
    - Otherwise the parser collected every recoverable error it could
      while syncing forward to the next top-level declaration; the AST
      returned is a partial Program containing whichever decls parsed
      cleanly. Callers wanting a hard fail can convert the diagnostics
      back into `raise AetherError(None, diagnostics=diags)`.

    This is the entry point the agent SDK, the LSP, and the
    `aether check --collect-errors` CLI mode use to surface every parse
    problem in one shot, rather than the fix-loop having to re-run the
    parser for each error one at a time.
    """
    tokens = tokenize(source, filename)
    p = Parser(tokens, collect_errors=True)
    ast = p.parse_program()
    return ast, list(p.diagnostics)


# Top-level keywords used as sync points for multi-error recovery.
_SYNC_TOP_LEVEL_KEYWORDS = (
    "function", "type", "record", "union", "const", "module", "import",
)


class Parser:
    def __init__(self, tokens: List[Token], collect_errors: bool = False):
        self.tokens = tokens
        self.i = 0
        self.collect_errors = collect_errors
        self.diagnostics: List[Diagnostic] = []

    # --- token helpers --------------------------------------------------

    def peek(self, offset: int = 0) -> Token:
        j = self.i + offset
        if j >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[j]

    def at_kw(self, *keywords: str, offset: int = 0) -> bool:
        t = self.peek(offset)
        return t.kind == "kw" and t.value in keywords

    def at_sym(self, *symbols: str, offset: int = 0) -> bool:
        t = self.peek(offset)
        return t.kind == "sym" and t.value in symbols

    def advance(self) -> Token:
        t = self.tokens[self.i]
        self.i += 1
        return t

    def expect_kw(self, kw: str) -> Token:
        t = self.peek()
        if t.kind != "kw" or t.value != kw:
            raise self.err(f"expected keyword '{kw}', got {self._show(t)}", t.pos,
                           suggestion=f"insert '{kw}' here")
        return self.advance()

    def expect_sym(self, sym: str) -> Token:
        t = self.peek()
        if t.kind != "sym" or t.value != sym:
            raise self.err(f"expected '{sym}', got {self._show(t)}", t.pos,
                           suggestion=f"insert '{sym}' here")
        return self.advance()

    def expect_ident(self) -> Token:
        t = self.peek()
        if t.kind != "ident":
            raise self.err(f"expected identifier, got {self._show(t)}", t.pos)
        return self.advance()

    def _show(self, t: Token) -> str:
        if t.kind == "eof":
            return "<eof>"
        return f"{t.kind}({t.value!r})"

    def err(self, msg: str, pos: Position, suggestion: Optional[str] = None) -> AetherError:
        return AetherError(Diagnostic(
            code="E0201", category="parse", severity="error",
            message=msg, position=pos, suggestion=suggestion, confidence=0.8,
        ))

    # --- program --------------------------------------------------------

    def parse_program(self) -> Dict[str, Any]:
        decls = []
        while self.peek().kind != "eof":
            if self.collect_errors:
                start_i = self.i
                try:
                    decls.append(self.parse_top_decl())
                except AetherError as e:
                    self.diagnostics.append(e.diag)
                    # Don't loop forever on the same token.
                    if self.i == start_i:
                        self.advance()
                    self._sync_to_top_level()
            else:
                decls.append(self.parse_top_decl())
        return {"kind": "Program", "decls": decls}

    def _sync_to_top_level(self) -> None:
        """Advance the cursor until we either hit a top-level keyword
        or eof. Used only in collect-errors mode."""
        while True:
            t = self.peek()
            if t.kind == "eof":
                return
            if t.kind == "kw" and t.value in _SYNC_TOP_LEVEL_KEYWORDS:
                return
            self.advance()

    def parse_top_decl(self) -> Dict[str, Any]:
        t = self.peek()
        if t.kind == "kw":
            if t.value == "function":
                return self.parse_function_decl()
            if t.value == "type":
                return self.parse_type_decl()
            if t.value == "record":
                return self.parse_record_decl()
            if t.value == "union":
                return self.parse_union_decl()
            if t.value == "const":
                return self.parse_const_decl()
            if t.value == "module":
                return self.parse_module_decl()
            if t.value == "import":
                return self.parse_import_decl()
        raise self.err(f"expected top-level declaration, got {self._show(t)}", t.pos,
                       suggestion="top-level must start with one of: module, import, function, type, record, union, const")

    # --- module / import -----------------------------------------------

    def parse_module_decl(self) -> Dict[str, Any]:
        kw = self.expect_kw("module")
        name = self.expect_ident().value
        capabilities = []
        exports = []
        while not self.at_kw("end"):
            if self.at_kw("requires"):
                self.advance()
                self.expect_kw("capability")
                cap = self.expect_ident().value
                capabilities.append(cap)
            elif self.at_kw("exports"):
                self.advance()
                exports.append(self.expect_ident().value)
                while self.at_sym(","):
                    self.advance()
                    exports.append(self.expect_ident().value)
            else:
                t = self.peek()
                raise self.err(f"unexpected token in module body: {self._show(t)}", t.pos)
        self.expect_kw("end")
        return {"kind": "ModuleDecl", "name": name,
                "capabilities": capabilities, "exports": exports,
                "pos": kw.pos.to_dict()}

    def parse_import_decl(self) -> Dict[str, Any]:
        kw = self.expect_kw("import")
        path = [self.expect_ident().value]
        while self.at_sym("."):
            self.advance()
            path.append(self.expect_ident().value)
        alias = None
        if self.at_kw("as"):
            self.advance()
            alias = self.expect_ident().value
        return {"kind": "ImportDecl", "path": path, "alias": alias,
                "pos": kw.pos.to_dict()}

    # --- type / record / union / const ----------------------------------

    def parse_type_decl(self) -> Dict[str, Any]:
        kw = self.expect_kw("type")
        name = self.expect_ident().value
        self.expect_sym("=")
        base = self.parse_type_expr()
        refinement = None
        if self.at_kw("where"):
            self.advance()
            refinement = self.parse_expr()
        return {"kind": "TypeDecl", "name": name, "base": base,
                "refinement": refinement, "pos": kw.pos.to_dict()}

    def parse_record_decl(self) -> Dict[str, Any]:
        kw = self.expect_kw("record")
        name = self.expect_ident().value
        self.expect_kw("do")
        fields = []
        while not self.at_kw("end"):
            fname = self.expect_ident().value
            self.expect_sym(":")
            ftype = self.parse_type_expr()
            fields.append({"name": fname, "type": ftype})
        self.expect_kw("end")
        return {"kind": "RecordDecl", "name": name, "fields": fields,
                "pos": kw.pos.to_dict()}

    def parse_union_decl(self) -> Dict[str, Any]:
        kw = self.expect_kw("union")
        name = self.expect_ident().value
        self.expect_kw("do")
        cases = []
        while self.at_kw("case"):
            self.advance()
            cname = self.expect_ident().value
            cparams = []
            if self.at_sym("("):
                self.advance()
                if not self.at_sym(")"):
                    cparams.append(self._parse_param())
                    while self.at_sym(","):
                        self.advance()
                        cparams.append(self._parse_param())
                self.expect_sym(")")
            cases.append({"name": cname, "params": cparams})
        self.expect_kw("end")
        return {"kind": "UnionDecl", "name": name, "cases": cases,
                "pos": kw.pos.to_dict()}

    def parse_const_decl(self) -> Dict[str, Any]:
        kw = self.expect_kw("const")
        name = self.expect_ident().value
        self.expect_sym(":")
        ty = self.parse_type_expr()
        self.expect_sym("=")
        value = self.parse_expr()
        return {"kind": "ConstDecl", "name": name, "type": ty, "value": value,
                "pos": kw.pos.to_dict()}

    # --- function ------------------------------------------------------

    def parse_function_decl(self) -> Dict[str, Any]:
        kw = self.expect_kw("function")
        name = self.expect_ident().value
        generics: List[str] = []
        # generic params: "<" IDENT { "," IDENT } ">" — only in this position
        if self.at_sym("<"):
            self.advance()
            generics.append(self.expect_ident().value)
            while self.at_sym(","):
                self.advance()
                generics.append(self.expect_ident().value)
            self.expect_sym(">")
        self.expect_sym("(")
        params: List[Dict[str, Any]] = []
        if not self.at_sym(")"):
            params.append(self._parse_param())
            while self.at_sym(","):
                self.advance()
                params.append(self._parse_param())
        self.expect_sym(")")
        self.expect_kw("returns")
        ret_type = self.parse_type_expr()
        requires_clauses: List[Dict[str, Any]] = []
        ensures_clauses: List[Dict[str, Any]] = []
        effects: List[Dict[str, Any]] = []
        # Contract clauses + effects can interleave
        while self.at_kw("requires") or self.at_kw("ensures") or self.at_kw("effects"):
            if self.at_kw("requires"):
                self.advance()
                requires_clauses.append(self.parse_expr())
            elif self.at_kw("ensures"):
                self.advance()
                ensures_clauses.append(self.parse_expr())
            elif self.at_kw("effects"):
                self.advance()
                effects = self.parse_effect_list()
        if not effects:
            raise self.err(
                f"function {name!r} must declare 'effects' (use 'effects pure' for no effects)",
                kw.pos, suggestion="add 'effects pure' before 'do'",
            )
        self.expect_kw("do")
        body = self.parse_block(end_kws=("end",))
        self.expect_kw("end")
        return {
            "kind": "FunctionDecl",
            "name": name,
            "generics": generics,
            "params": params,
            "return_type": ret_type,
            "requires": requires_clauses,
            "ensures": ensures_clauses,
            "effects": effects,
            "body": body,
            "pos": kw.pos.to_dict(),
        }

    def _parse_param(self) -> Dict[str, Any]:
        n = self.expect_ident().value
        self.expect_sym(":")
        ty = self.parse_type_expr()
        return {"name": n, "type": ty}

    def parse_effect_list(self) -> List[Dict[str, Any]]:
        out = [self.parse_effect()]
        while self.at_sym(","):
            self.advance()
            out.append(self.parse_effect())
        return out

    def parse_effect(self) -> Dict[str, Any]:
        if self.at_kw("pure"):
            self.advance()
            return {"path": ["pure"], "arg": None}
        # dotted_ident
        path = [self.expect_ident().value]
        while self.at_sym("."):
            self.advance()
            path.append(self.expect_ident().value)
        arg = None
        if self.at_sym("("):
            self.advance()
            arg = self.parse_expr()
            self.expect_sym(")")
        return {"path": path, "arg": arg}

    # --- type expressions ----------------------------------------------

    def parse_type_expr(self) -> Dict[str, Any]:
        # function ( T1, T2, ... ) returns T
        if self.at_kw("function"):
            self.advance()
            self.expect_sym("(")
            params: List[Dict[str, Any]] = []
            if not self.at_sym(")"):
                params.append(self.parse_type_expr())
                while self.at_sym(","):
                    self.advance()
                    params.append(self.parse_type_expr())
            self.expect_sym(")")
            self.expect_kw("returns")
            ret = self.parse_type_expr()
            return {"kind": "FunctionType", "params": params, "returns": ret}
        # IDENT [<...>]
        name = self.expect_ident().value
        args: List[Dict[str, Any]] = []
        if self.at_sym("<"):
            # commit: type generic
            self.advance()
            args.append(self.parse_type_expr())
            while self.at_sym(","):
                self.advance()
                args.append(self.parse_type_expr())
            self.expect_sym(">")
            return {"kind": "GenericType", "name": name, "args": args}
        return {"kind": "TypeName", "name": name}

    # --- block / statements --------------------------------------------

    def parse_block(self, end_kws: tuple) -> List[Dict[str, Any]]:
        stmts: List[Dict[str, Any]] = []
        while not (self.peek().kind == "kw" and self.peek().value in end_kws):
            if self.peek().kind == "eof":
                t = self.peek()
                raise self.err(f"unexpected end of file inside block; expected one of {end_kws}", t.pos)
            stmts.append(self.parse_stmt())
        return stmts

    def parse_stmt(self) -> Dict[str, Any]:
        t = self.peek()
        if t.kind == "kw":
            v = t.value
            if v == "let":
                return self._let_or_var("let")
            if v == "var":
                return self._let_or_var("var")
            if v == "if":
                return self.parse_if_stmt()
            if v == "while":
                return self.parse_while_stmt()
            if v == "for":
                return self.parse_for_stmt()
            if v == "match":
                return self.parse_match_stmt()
            if v == "return":
                return self.parse_return_stmt()
            if v == "break":
                self.advance()
                return {"kind": "Break"}
            if v == "continue":
                self.advance()
                return {"kind": "Continue"}
        # assign vs expr_stmt: lookahead for IDENT '='
        if t.kind == "ident" and self.peek(1).kind == "sym" and self.peek(1).value == "=":
            name = self.advance().value
            self.advance()  # =
            value = self.parse_expr()
            return {"kind": "Assign", "target": name, "value": value, "pos": t.pos.to_dict()}
        # otherwise, expression statement
        e = self.parse_expr()
        return {"kind": "ExprStmt", "expr": e}

    def _let_or_var(self, which: str) -> Dict[str, Any]:
        kw = self.advance()
        name = self.expect_ident().value
        ty = None
        if self.at_sym(":"):
            self.advance()
            ty = self.parse_type_expr()
        self.expect_sym("=")
        value = self.parse_expr()
        return {"kind": "Let" if which == "let" else "Var",
                "name": name, "type": ty, "value": value,
                "pos": kw.pos.to_dict()}

    def parse_if_stmt(self) -> Dict[str, Any]:
        kw = self.expect_kw("if")
        cond = self.parse_expr()
        self.expect_kw("then")
        then_block = self.parse_block(end_kws=("elif", "else", "end"))
        elifs: List[Dict[str, Any]] = []
        else_block: Optional[List[Dict[str, Any]]] = None
        while self.at_kw("elif"):
            self.advance()
            c = self.parse_expr()
            self.expect_kw("then")
            b = self.parse_block(end_kws=("elif", "else", "end"))
            elifs.append({"cond": c, "body": b})
        if self.at_kw("else"):
            self.advance()
            else_block = self.parse_block(end_kws=("end",))
        self.expect_kw("end")
        return {"kind": "If", "cond": cond, "then": then_block,
                "elifs": elifs, "else": else_block,
                "pos": kw.pos.to_dict()}

    def parse_while_stmt(self) -> Dict[str, Any]:
        kw = self.expect_kw("while")
        cond = self.parse_expr()
        self.expect_kw("do")
        body = self.parse_block(end_kws=("end",))
        self.expect_kw("end")
        return {"kind": "While", "cond": cond, "body": body,
                "pos": kw.pos.to_dict()}

    def parse_for_stmt(self) -> Dict[str, Any]:
        kw = self.expect_kw("for")
        var = self.expect_ident().value
        self.expect_kw("in")
        iterable = self.parse_expr()
        self.expect_kw("do")
        body = self.parse_block(end_kws=("end",))
        self.expect_kw("end")
        return {"kind": "For", "var": var, "iter": iterable, "body": body,
                "pos": kw.pos.to_dict()}

    def parse_match_stmt(self) -> Dict[str, Any]:
        kw = self.expect_kw("match")
        scrutinee = self.parse_expr()
        self.expect_kw("do")
        arms: List[Dict[str, Any]] = []
        while self.at_kw("case"):
            self.advance()
            pat = self.parse_pattern()
            self.expect_kw("do")
            body = self.parse_block(end_kws=("end",))
            self.expect_kw("end")
            arms.append({"pattern": pat, "body": body})
        self.expect_kw("end")
        return {"kind": "Match", "scrutinee": scrutinee, "arms": arms,
                "pos": kw.pos.to_dict()}

    def parse_return_stmt(self) -> Dict[str, Any]:
        kw = self.expect_kw("return")
        value = None
        # heuristic: a return can be followed by EOF, end, else, elif, case, or another stmt keyword
        t = self.peek()
        terminators_kw = {"end", "else", "elif", "case"}
        if not (t.kind == "kw" and t.value in terminators_kw) and t.kind != "eof":
            # if next token is one of the statement-starters, no expression follows
            if not (t.kind == "kw" and t.value in {"let", "var", "if", "while", "for", "match", "return", "break", "continue"}):
                value = self.parse_expr()
        return {"kind": "Return", "value": value, "pos": kw.pos.to_dict()}

    # --- patterns ------------------------------------------------------

    def parse_pattern(self) -> Dict[str, Any]:
        t = self.peek()
        # wildcard
        if t.kind == "ident" and t.value == "_":
            self.advance()
            return {"kind": "WildcardPat"}
        # literal patterns
        if t.kind in ("int", "float", "string"):
            self.advance()
            return {"kind": "LiteralPat", "value": t.value, "lit_kind": t.kind}
        if t.kind == "kw" and t.value in ("true", "false", "null"):
            self.advance()
            return {"kind": "LiteralPat", "value": t.value, "lit_kind": "kw"}
        # IDENT — either constructor pattern or binding
        if t.kind == "ident":
            self.advance()
            name = t.value
            # qualified constructor: IDENT { "." IDENT }
            path = [name]
            while self.at_sym("."):
                self.advance()
                path.append(self.expect_ident().value)
            if self.at_sym("("):
                self.advance()
                args: List[Dict[str, Any]] = []
                if not self.at_sym(")"):
                    args.append(self.parse_pattern())
                    while self.at_sym(","):
                        self.advance()
                        args.append(self.parse_pattern())
                self.expect_sym(")")
                pat: Dict[str, Any] = {"kind": "ConstructorPat", "path": path, "args": args}
            else:
                if len(path) > 1:
                    raise self.err("qualified name without (...) is not a valid pattern", t.pos)
                pat = {"kind": "BindPat", "name": name}
            if self.at_kw("as"):
                self.advance()
                alias = self.expect_ident().value
                pat = {"kind": "AsPat", "pattern": pat, "name": alias}
            return pat
        raise self.err(f"expected pattern, got {self._show(t)}", t.pos)

    # --- expressions ----------------------------------------------------
    # implemented with explicit precedence climbing per the EBNF order

    def parse_expr(self) -> Dict[str, Any]:
        return self._parse_or()

    def _binop_loop(self, sub: Callable[[], Dict[str, Any]], ops: tuple) -> Dict[str, Any]:
        left = sub()
        while True:
            t = self.peek()
            matched = None
            if t.kind == "sym" and t.value in ops:
                matched = t.value
            elif t.kind == "kw" and t.value in ops:
                matched = t.value
            if matched is None:
                return left
            self.advance()
            right = sub()
            left = {"kind": "BinOp", "op": matched, "left": left, "right": right}

    def _parse_or(self) -> Dict[str, Any]:
        return self._binop_loop(self._parse_and, ("or",))

    def _parse_and(self) -> Dict[str, Any]:
        return self._binop_loop(self._parse_implies, ("and",))

    def _parse_implies(self) -> Dict[str, Any]:
        # right-assoc
        left = self._parse_not()
        if self.at_kw("implies"):
            self.advance()
            right = self._parse_implies()
            return {"kind": "BinOp", "op": "implies", "left": left, "right": right}
        return left

    def _parse_not(self) -> Dict[str, Any]:
        if self.at_kw("not"):
            self.advance()
            v = self._parse_not()
            return {"kind": "UnaryOp", "op": "not", "value": v}
        return self._parse_eq()

    def _parse_eq(self) -> Dict[str, Any]:
        return self._binop_loop(self._parse_rel, ("==", "!="))

    def _parse_rel(self) -> Dict[str, Any]:
        return self._binop_loop(self._parse_bor, ("<", "<=", ">", ">=", "is", "in"))

    def _parse_bor(self) -> Dict[str, Any]:
        return self._binop_loop(self._parse_bxor, ("bor",))

    def _parse_bxor(self) -> Dict[str, Any]:
        return self._binop_loop(self._parse_band, ("bxor",))

    def _parse_band(self) -> Dict[str, Any]:
        return self._binop_loop(self._parse_shift, ("band",))

    def _parse_shift(self) -> Dict[str, Any]:
        return self._binop_loop(self._parse_add, ("shl", "shr"))

    def _parse_add(self) -> Dict[str, Any]:
        return self._binop_loop(self._parse_mul, ("+", "-"))

    def _parse_mul(self) -> Dict[str, Any]:
        return self._binop_loop(self._parse_unary, ("*", "/", "%"))

    def _parse_unary(self) -> Dict[str, Any]:
        if self.at_sym("-"):
            self.advance()
            v = self._parse_postfix()
            return {"kind": "UnaryOp", "op": "neg", "value": v}
        return self._parse_postfix()

    def _parse_postfix(self) -> Dict[str, Any]:
        e = self._parse_primary()
        while True:
            if self.at_sym("("):
                self.advance()
                args: List[Dict[str, Any]] = []
                if not self.at_sym(")"):
                    args.append(self.parse_expr())
                    while self.at_sym(","):
                        self.advance()
                        args.append(self.parse_expr())
                self.expect_sym(")")
                e = {"kind": "Call", "func": e, "args": args}
            elif self.at_sym("."):
                self.advance()
                fname = self.expect_ident().value
                e = {"kind": "Field", "value": e, "name": fname}
            elif self.at_sym("["):
                self.advance()
                idx = self.parse_expr()
                self.expect_sym("]")
                e = {"kind": "Index", "value": e, "index": idx}
            else:
                return e

    def _parse_primary(self) -> Dict[str, Any]:
        t = self.peek()
        # literals
        if t.kind == "int":
            self.advance()
            return {"kind": "IntLit", "value": t.value}
        if t.kind == "float":
            self.advance()
            return {"kind": "FloatLit", "value": t.value}
        if t.kind == "string":
            self.advance()
            # Positioned: E0723 (hardcoded credential) anchors on the
            # literal itself, and reported `line 0, col 0` without it.
            return {"kind": "StringLit", "value": t.value, "pos": t.pos.to_dict()}
        if t.kind == "kw" and t.value in ("true", "false"):
            self.advance()
            return {"kind": "BoolLit", "value": t.value == "true"}
        if t.kind == "kw" and t.value == "null":
            self.advance()
            return {"kind": "NullLit"}
        # special function-like keywords
        if t.kind == "kw" and t.value == "old":
            self.advance()
            self.expect_sym("(")
            v = self.parse_expr()
            self.expect_sym(")")
            return {"kind": "Old", "value": v}
        if t.kind == "kw" and t.value in ("self", "result"):
            self.advance()
            return {"kind": "Ident", "name": t.value}
        # parenthesised
        if t.kind == "sym" and t.value == "(":
            self.advance()
            e = self.parse_expr()
            self.expect_sym(")")
            return e
        # if-expression
        if t.kind == "kw" and t.value == "if":
            return self._parse_if_expr()
        # match-expression
        if t.kind == "kw" and t.value == "match":
            return self._parse_match_expr()
        if t.kind == "sym" and t.value == "[":
            self.advance()
            elems: List[Dict[str, Any]] = []
            if not self.at_sym("]"):
                elems.append(self.parse_expr())
                while self.at_sym(","):
                    self.advance()
                    elems.append(self.parse_expr())
            self.expect_sym("]")
            return {"kind": "ListLit", "elems": elems}
        # map literal
        if t.kind == "sym" and t.value == "{":
            self.advance()
            entries: List[Dict[str, Any]] = []
            if not self.at_sym("}"):
                k = self.parse_expr()
                self.expect_sym(":")
                v = self.parse_expr()
                entries.append({"key": k, "value": v})
                while self.at_sym(","):
                    self.advance()
                    k = self.parse_expr()
                    self.expect_sym(":")
                    v = self.parse_expr()
                    entries.append({"key": k, "value": v})
            self.expect_sym("}")
            return {"kind": "MapLit", "entries": entries}
        # identifier
        if t.kind == "ident":
            self.advance()
            return {"kind": "Ident", "name": t.value}
        raise self.err(f"expected expression, got {self._show(t)}", t.pos)

    def _parse_if_expr(self) -> Dict[str, Any]:
        self.expect_kw("if")
        cond = self.parse_expr()
        self.expect_kw("then")
        then_e = self.parse_expr()
        elifs: List[Dict[str, Any]] = []
        while self.at_kw("elif"):
            self.advance()
            c = self.parse_expr()
            self.expect_kw("then")
            elifs.append({"cond": c, "value": self.parse_expr()})
        self.expect_kw("else")
        else_e = self.parse_expr()
        self.expect_kw("end")
        return {"kind": "IfExpr", "cond": cond, "then": then_e,
                "elifs": elifs, "else": else_e}

    def _parse_match_expr(self) -> Dict[str, Any]:
        self.expect_kw("match")
        scr = self.parse_expr()
        self.expect_kw("do")
        arms: List[Dict[str, Any]] = []
        while self.at_kw("case"):
            self.advance()
            pat = self.parse_pattern()
            self.expect_kw("do")
            value = self.parse_expr()
            self.expect_kw("end")
            arms.append({"pattern": pat, "value": value})
        self.expect_kw("end")
        return {"kind": "MatchExpr", "scrutinee": scr, "arms": arms}
