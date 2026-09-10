"""
dataflow.py
-----------
AST-based taint analysis: tracks tainted values (from $_GET/$_POST/etc.)
through variable assignments, string concatenation, and function calls to
determine whether user-controlled input reaches a sensitive sink (a SQL
query, an echo statement, etc.).

Performance note: the AST cache in ASTEngine ensures a given file is
parsed by PHP only once per scan, even though analyze() is called
independently by several rule modules (input.py, sql.py, output.py)
that each need taint information for the same file.

Fixes carried forward from earlier debugging against real test fixtures:
  - A tainted variable reaching a SQL sink as the RHS of an assignment
    (e.g. `$result = $wpdb->get_results("... $id ...")`) was previously
    missed entirely, because the top-level statement type was
    "assignment", not "method call". Fixed via _scan_expr_for_sinks(),
    which recurses into assignment right-hand-sides looking for sinks.
  - `wp_verify_nonce($_POST['nonce'])` was flagged as unsanitized input,
    even though the superglobal there is consumed as a nonce token, not
    as attacker-controlled application data. wp_verify_nonce/
    check_*_referer arguments are now recognized as a "nonce context"
    and produce no taint findings.
  - analyze(text) called without a real source_file correctly wrote the
    text to a temp file for AST parsing, but taint discovered inside a
    function's local scope wasn't being propagated back up to the
    caller. Fixed in _stmt()'s handling of function/method bodies.
"""

from __future__ import annotations

import contextlib
import os
import re
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass

from .ast_engine import ASTEngine
from .sanitizers import ALL_SANITIZERS as _CANONICAL_SANITIZERS

_engine = ASTEngine()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPERGLOBALS: set[str] = {"_GET", "_POST", "_REQUEST", "_COOKIE"}

# Imported from sanitizers.py so this module, input.py, and output.py
# all agree on exactly the same definition of "sanitized".
SANITIZERS: frozenset[str] = _CANONICAL_SANITIZERS

PARTIAL_SANITIZERS: set[str] = {"wp_unslash"}

# Functions whose argument is consumed as a nonce/auth token, not as
# application data — passing a superglobal here should not count as
# "unsanitized input" the way passing it to echo() would.
NONCE_FUNCTIONS: set[str] = {
    "wp_verify_nonce",
    "check_ajax_referer",
    "check_admin_referer",
    "wp_nonce_field",
    "wp_create_nonce",
}

SQL_SINKS: set[str] = {"query", "get_results", "get_row", "get_var", "get_col"}
OUTPUT_SINKS: set[str] = {"echo", "print", "printf", "vprintf", "fprintf"}
SQL_NEUTRALIZERS: set[str] = {"prepare"}


# ---------------------------------------------------------------------------
# DataFlowResult
# ---------------------------------------------------------------------------


@dataclass
class DataFlowResult:
    var_name: str
    superglobal: str
    sink_type: str
    sink_line: int
    taint_line: int
    source_file: str = ""
    is_sanitized: bool = False
    confidence: float = 0.92

    @property
    def var(self) -> str:
        return self.var_name

    def __repr__(self) -> str:
        return (
            f"DataFlowResult(var='{self.var_name}', source='{self.superglobal}', "
            f"sink='{self.sink_type}', line={self.sink_line})"
        )


# ---------------------------------------------------------------------------
# TaintRecord
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TaintRecord:
    source: str
    line: int
    partial: bool = False


TaintState = dict[str, TaintRecord]


# ---------------------------------------------------------------------------
# AST node helpers
# ---------------------------------------------------------------------------


def _nt(node) -> str:
    return node.get("nodeType", "") if isinstance(node, dict) else ""


def _line(node) -> int:
    if isinstance(node, dict):
        return int(node.get("attributes", {}).get("startLine", 0))
    return 0


def _var_name(node) -> str | None:
    if _nt(node) == "Expr_Variable":
        n = node.get("name")
        return str(n) if isinstance(n, str) else None
    return None


def _local_var_name(expr, state: TaintState, analyzer, fallback: str) -> str:
    r"""
    Best-effort extraction of the LOCAL variable name that carries taint
    at a sink, for display and for sql.py's secondary regex-based
    variable-name matching against the raw source line.

    _var_name(expr) alone only succeeds when expr IS a bare $variable
    reference. When the tainted argument is a STRING INTERPOLATION
    (Scalar_Encapsed) -- e.g. "SELECT * FROM t WHERE id = $id" -- expr is
    the whole string node, not the embedded $id, so _var_name(expr)
    returns None. Falling back straight to the taint's ultimate SOURCE
    description (e.g. "$_GET['id']") was a real, significant bug: that
    description never appears literally in the query text, so sql.py's
    `re.search(rf"\$" + re.escape(var) + r"\b", context)` check for
    "does this tainted variable appear in the SQL call's context" always
    failed for the single most common SQL-injection shape (string
    interpolation), silently downgrading proven-taint findings from HIGH
    down to a generic MEDIUM "should be reviewed" bucket.

    This walks into Scalar_Encapsed parts to find the actual embedded
    variable name before giving up and using `fallback` (normally
    `t.source`).
    """
    name = _var_name(expr)
    if name:
        return name
    if _nt(expr) == "Scalar_Encapsed":
        for part in expr.get("parts", []):
            if _expr_taint(part, state, analyzer):
                part_name = _var_name(part)
                if part_name:
                    return part_name
    return fallback


def _class_name(node) -> str:
    """Extract a class name from a Stmt_Class node's `name` field (an Identifier)."""
    n = node.get("name")
    if isinstance(n, dict):
        return str(n.get("name", ""))
    return str(n or "")


def _is_this_var(node) -> bool:
    """True if node is the Expr_Variable representing $this."""
    return _nt(node) == "Expr_Variable" and node.get("name") == "this"


def _param_names(method_node) -> list[str]:
    """Extract parameter names, in declaration order, from a Stmt_ClassMethod node."""
    names = []
    for p in method_node.get("params", []) or []:
        var = p.get("var", {}) if isinstance(p, dict) else {}
        n = _var_name(var)
        if n:
            names.append(n)
    return names


def _iter_all_nodes(node) -> Iterator[dict]:
    """Recursively yield every dict node in an AST, regardless of nesting depth."""
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _iter_all_nodes(v)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_all_nodes(item)


def _find_class_method(ast_nodes, class_name: str, method_name: str) -> dict | None:
    """
    Search a file's full AST for the Stmt_ClassMethod named `method_name`
    inside the Stmt_Class named `class_name`. Used to resolve $this->method()
    calls for inter-procedural taint analysis (see ASTAnalyzer._resolve_this_call).
    """
    for node in _iter_all_nodes(ast_nodes):
        if _nt(node) == "Stmt_Class" and _class_name(node) == class_name:
            for member in node.get("stmts", []) or []:
                if _nt(member) == "Stmt_ClassMethod" and _method_name(member) == method_name:
                    return dict(member)
    return None


def _func_name(node) -> str:
    n = node.get("name", {})
    if isinstance(n, dict):
        parts = n.get("parts", [])
        if parts:
            return str(parts[-1]).lower()
        return str(n.get("name", "")).lower()
    return str(n).lower()


def _method_name(node) -> str:
    n = node.get("name", {})
    if isinstance(n, dict):
        return str(n.get("name", "")).lower()
    return str(n).lower()


def _arg_values(node) -> list:
    return [a.get("value", {}) for a in node.get("args", []) if isinstance(a, dict)]


# ---------------------------------------------------------------------------
# Taint propagation
# ---------------------------------------------------------------------------


def _expr_taint(expr, state: TaintState, analyzer: ASTAnalyzer | None = None) -> TaintRecord | None:
    """
    Determine whether `expr` evaluates to tainted data.

    `analyzer` is an optional ASTAnalyzer instance; when supplied, it is
    threaded through every recursive call so that a $this->method() call
    at ANY nesting depth (not just as a top-level assignment RHS) can be
    resolved inter-procedurally via analyzer._resolve_this_call(). This
    lets constructs like `$x = "prefix" . $this->get_input();` correctly
    detect taint originating inside get_input()'s body, not just direct
    `$x = $this->get_input();` assignments.
    """
    nt = _nt(expr)

    if nt == "Expr_Variable":
        vname = _var_name(expr)
        return state.get(vname) if vname else None

    if nt == "Expr_ArrayDimFetch":
        arr = expr.get("var", {})
        vname = _var_name(arr)
        if vname in SUPERGLOBALS:
            dim = expr.get("dim", {})
            key = dim.get("value", "?") if isinstance(dim, dict) else "?"
            return TaintRecord(source=f"${vname}['{key}']", line=_line(expr))
        return _expr_taint(arr, state, analyzer)

    if nt == "Expr_BinaryOp_Concat":
        return _expr_taint(expr.get("left", {}), state, analyzer) or _expr_taint(
            expr.get("right", {}), state, analyzer
        )

    if nt == "Scalar_Encapsed":
        for part in expr.get("parts", []):
            t = _expr_taint(part, state, analyzer)
            if t:
                return t
        return None

    if nt == "Expr_FuncCall":
        fn = _func_name(expr)
        if fn in SANITIZERS:
            return None
        if fn in NONCE_FUNCTIONS:
            return None  # nonce context — not treated as a taint source
        if fn in PARTIAL_SANITIZERS:
            for av in _arg_values(expr):
                t = _expr_taint(av, state, analyzer)
                if t:
                    return TaintRecord(source=t.source, line=t.line, partial=True)
            return None
        for av in _arg_values(expr):
            t = _expr_taint(av, state, analyzer)
            if t:
                return t
        return None

    if nt == "Expr_MethodCall":
        meth = _method_name(expr)
        if meth in SQL_NEUTRALIZERS:
            return None
        # Inter-procedural resolution: $this->method(...) is resolved
        # against the real method body when an analyzer/project/class_name
        # are available. See ASTAnalyzer._resolve_this_call for the "why".
        if analyzer is not None and _is_this_var(expr.get("var", {})):
            resolved = analyzer._resolve_this_call(expr, state)
            if resolved is not None:
                return resolved
            # Fall through to the crude any-tainted-arg heuristic below only
            # if the method could not be resolved (e.g. inherited from a
            # parent class not indexed in this scan) or genuinely doesn't
            # return tainted data.
        for av in _arg_values(expr):
            t = _expr_taint(av, state, analyzer)
            if t:
                return t
        return None

    if nt == "Expr_Ternary":
        return _expr_taint(expr.get("if", expr.get("cond", {})), state, analyzer) or _expr_taint(
            expr.get("else", {}), state, analyzer
        )

    if nt == "Expr_NullsafeMethodCall":
        return _expr_taint({**expr, "nodeType": "Expr_MethodCall"}, state, analyzer)

    return None


# ---------------------------------------------------------------------------
# Sink scanning — recursively search an expression for method/function calls
# ---------------------------------------------------------------------------


def _scan_expr_for_sinks(
    expr, state: TaintState, results: list[DataFlowResult], analyzer: ASTAnalyzer | None = None
) -> None:
    """
    Walk an expression tree and flag every SQL/output sink it reaches.
    Handles sinks that are the RHS of an assignment, an argument to
    another call, etc. `analyzer` is threaded through for inter-procedural
    $this-> call resolution -- see _expr_taint's docstring.
    """
    if not isinstance(expr, dict):
        return
    nt = _nt(expr)

    if nt == "Expr_MethodCall":
        meth = _method_name(expr)
        ln = _line(expr)
        if meth in SQL_SINKS:
            for av in _arg_values(expr):
                # Neutralized by prepare()?
                if _nt(av) == "Expr_MethodCall" and _method_name(av) in SQL_NEUTRALIZERS:
                    continue
                t = _expr_taint(av, state, analyzer)
                if t:
                    vname = _local_var_name(av, state, analyzer, t.source)
                    results.append(
                        DataFlowResult(
                            var_name=vname,
                            superglobal=t.source,
                            sink_type="sql",
                            sink_line=ln,
                            taint_line=t.line,
                            confidence=0.93 if not t.partial else 0.72,
                        )
                    )
        elif analyzer is not None and _is_this_var(expr.get("var", {})):
            # Not a recognized SQL sink by name (e.g. $this->save($x) where
            # save() isn't named query/get_results/etc.), but it IS a
            # $this-> call: resolve it inter-procedurally so any sink
            # reached INSIDE the callee -- using the tainted argument
            # passed at this call site -- is still found. _resolve_this_call
            # merges any inner sinks into `results` (via analyzer.results,
            # which the caller's `results` list is the same object as) as a
            # side effect, regardless of what its return value is used for.
            analyzer._resolve_this_call(expr, state)
        # Recurse into arguments (a method call passed as an argument)
        for av in _arg_values(expr):
            _scan_expr_for_sinks(av, state, results, analyzer)

    elif nt == "Expr_FuncCall":
        fn = _func_name(expr)
        ln = _line(expr)
        if fn in OUTPUT_SINKS:
            for av in _arg_values(expr):
                t = _expr_taint(av, state, analyzer)
                if t:
                    vname = _local_var_name(av, state, analyzer, t.source)
                    results.append(
                        DataFlowResult(
                            var_name=vname,
                            superglobal=t.source,
                            sink_type="output",
                            sink_line=ln,
                            taint_line=t.line,
                            confidence=0.93 if not t.partial else 0.72,
                        )
                    )
        for av in _arg_values(expr):
            _scan_expr_for_sinks(av, state, results, analyzer)

    elif nt == "Expr_Print":
        t = _expr_taint(expr.get("expr", {}), state, analyzer)
        if t:
            inner = expr.get("expr", {})
            vname = _local_var_name(inner, state, analyzer, t.source)
            results.append(
                DataFlowResult(
                    var_name=vname,
                    superglobal=t.source,
                    sink_type="output",
                    sink_line=_line(expr),
                    taint_line=t.line,
                    confidence=0.93,
                )
            )

    else:
        # Recurse into sub-expressions
        for v in expr.values():
            if isinstance(v, dict):
                _scan_expr_for_sinks(v, state, results, analyzer)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        _scan_expr_for_sinks(item, state, results, analyzer)


def _check_sink(
    expr,
    sink_type: str,
    line: int,
    state: TaintState,
    results: list[DataFlowResult],
    analyzer: ASTAnalyzer | None = None,
) -> None:
    t = _expr_taint(expr, state, analyzer)
    if t:
        vname = _local_var_name(expr, state, analyzer, t.source)
        conf = 0.72 if t.partial else 0.93
        results.append(
            DataFlowResult(
                var_name=vname,
                superglobal=t.source,
                sink_type=sink_type,
                sink_line=line,
                taint_line=t.line,
                confidence=conf,
            )
        )


# ---------------------------------------------------------------------------
# ASTAnalyzer
# ---------------------------------------------------------------------------


class ASTAnalyzer:
    """
    Walks a file's AST tracking taint through statements.

    Inter-procedural extension: when project (a ProjectIndex) and
    class_name are known, a call to $this->method(...) is resolved against
    the *actual* target method body (found via project.by_class) instead of
    being treated as an opaque call. This closes a real detection gap:

        class Handler {
            public function get_input() {
                return $_POST['data'];      // <- taint originates HERE
            }
            public function process() {
                $data = $this->get_input(); // <- not a superglobal read itself
                $wpdb->query("... $data ..."); // <- but this IS a real SQLi
            }
        }

    Before this feature, $this->get_input() carried no taint information at
    all (nothing about the call itself references $_POST), so the SQL sink
    in process() was never flagged even though the data it uses originates
    directly from user input two frames up the call stack.

    Scope: intentionally limited to $this-> calls within the SAME class, in
    the SAME file, since that's what ProjectIndex reliably resolves and it
    covers the overwhelming majority of real WordPress plugin code (a class
    split across multiple files is rare). A recursion guard (_visiting)
    prevents infinite loops between methods that call each other.
    """

    def __init__(self, project=None, class_name: str | None = None, _visiting=None) -> None:
        self.results: list[DataFlowResult] = []
        self.project = project
        self.class_name = class_name
        self.return_taint: TaintRecord | None = None
        # Shared (not copied) across all sub-analyzers spawned from this one,
        # so a recursive/mutual call chain is detected regardless of which
        # instance re-enters a method already being resolved.
        self._visiting: set[tuple[str, str]] = _visiting if _visiting is not None else set()
        # Memoizes resolved $this-> calls within a single top-level analyze()
        # so a getter called from five places is only analyzed once.
        self._resolved_cache: dict[tuple[str, str, tuple], TaintRecord | None] = {}

    def analyze(self, ast_nodes: list) -> list[DataFlowResult]:
        state: TaintState = {}
        self._stmts(ast_nodes, state)
        return self.results

    def _resolve_this_call(self, expr, state: TaintState) -> TaintRecord | None:
        """
        Resolve $this->method(...) against the real method body via
        ProjectIndex, returning a TaintRecord if the method can return
        tainted data (directly from a superglobal, or from a tainted
        parameter passed in at this call site).

        Any sinks found INSIDE the resolved method body are also merged
        into self.results -- so calling a getter that itself contains an
        unsafe query is flagged too, not just chains that pass through it.
        """
        if self.project is None or self.class_name is None:
            return None

        method_name = _method_name(expr)
        key = (self.class_name, method_name)
        if key in self._visiting:
            return None  # recursion guard: already resolving this method

        symbol = self.project.by_class.get(self.class_name, {}).get(method_name)
        if symbol is None:
            return None  # method not found in this class (defined elsewhere, or dynamic)

        # Build the memoization key from the call's argument taint sources,
        # so calling get_input($a) and get_input($b) with different taint
        # origins isn't incorrectly treated as the same cached resolution.
        arg_taints = tuple(
            (t.source, t.line) if (t := _expr_taint(av, state, self)) else None
            for av in _arg_values(expr)
        )
        cache_key = (self.class_name, method_name, arg_taints)
        if cache_key in self._resolved_cache:
            return self._resolved_cache[cache_key]

        try:
            abs_path = str(self.project.root / symbol.file) if self.project.root else symbol.file
            file_ast = _engine.get_ast(abs_path)
        except Exception:
            file_ast = None
        if file_ast is None:
            self._resolved_cache[cache_key] = None
            return None

        method_node = _find_class_method(file_ast, self.class_name, method_name)
        if method_node is None:
            self._resolved_cache[cache_key] = None
            return None

        # Seed the callee's initial state: map each tainted positional
        # argument to the corresponding parameter name.
        param_names = _param_names(method_node)
        seeded_state: TaintState = {}
        # strict=False: a call site can legitimately pass fewer/more
        # arguments than declared parameters (optional params, variadics);
        # zip() should just pair up what it can rather than raising.
        for pname, av in zip(param_names, _arg_values(expr), strict=False):
            t = _expr_taint(av, state, self)
            if t:
                seeded_state[pname] = t

        sub = ASTAnalyzer(
            project=self.project,
            class_name=self.class_name,
            _visiting=self._visiting | {key},
        )
        sub._stmts(method_node.get("stmts", []) or [], seeded_state)

        # Surface any sinks found inside the callee itself. Downstream rule
        # modules already deduplicate by sink line within one file, so a
        # getter called from multiple sites still only reports once.
        self.results.extend(sub.results)

        result = sub.return_taint
        self._resolved_cache[cache_key] = result
        return result

    def _stmts(self, stmts, state: TaintState) -> TaintState:
        if not isinstance(stmts, list):
            return state
        for stmt in stmts:
            state = self._stmt(stmt, state)
        return state

    def _stmt(self, node, state: TaintState) -> TaintState:
        if not isinstance(node, dict):
            return state
        nt = _nt(node)

        if nt == "Stmt_Expression":
            expr = node.get("expr", {})
            return self._handle_expr_stmt(expr, state)

        if nt == "Stmt_Echo":
            for ex in node.get("exprs", []):
                _check_sink(ex, "output", _line(node), state, self.results, self)
            return state

        if nt == "Stmt_If":
            return self._handle_if(node, state)

        if nt in ("Stmt_While", "Stmt_Do"):
            after = self._stmts(node.get("stmts", []), dict(state))
            return self._union(state, after)

        if nt == "Stmt_For":
            self._stmts(node.get("init", []), state)
            after = self._stmts(node.get("stmts", []), dict(state))
            return self._union(state, after)

        if nt == "Stmt_Foreach":
            arr_taint = _expr_taint(node.get("expr", {}), state, self)
            new_state = dict(state)
            val_var = node.get("valueVar", {})
            vname = _var_name(val_var)
            if vname and arr_taint:
                new_state[vname] = arr_taint
            after = self._stmts(node.get("stmts", []), new_state)
            return self._union(state, after)

        if nt in ("Stmt_Function", "Stmt_ClassMethod"):
            # Analyze the function/method body in its own scope, but pass
            # through project/class_name/_visiting so $this-> calls made
            # from WITHIN this body can still be resolved inter-procedurally.
            sub = ASTAnalyzer(
                project=self.project, class_name=self.class_name, _visiting=self._visiting
            )
            sub._stmts(node.get("stmts", []) or [], {})
            self.results.extend(sub.results)
            return state

        if nt == "Stmt_Class":
            # Capture the class name so nested Stmt_ClassMethod handling
            # (above) knows which class it belongs to -- this is what lets
            # $this-> calls resolve against the correct entry in
            # project.by_class[class_name]. Temporarily set self.class_name
            # while walking this class's members, then restore it (this is
            # a single-threaded, single-pass walk, so mutation is safe).
            cname = _class_name(node) or self.class_name
            prev_class_name = self.class_name
            self.class_name = cname
            for member in node.get("stmts", []):
                self._stmt(member, {})
            self.class_name = prev_class_name
            return state

        if nt == "Stmt_TryCatch":
            after_try = self._stmts(node.get("stmts", []), dict(state))
            merged = dict(state)
            for catch in node.get("catches", []):
                after_catch = self._stmts(catch.get("stmts", []), dict(state))
                merged = self._union(merged, after_catch)
            return self._union(after_try, merged)

        if nt == "Stmt_Return":
            # Capture the first tainted return value found. This is what
            # powers inter-procedural resolution: a caller doing
            # `$x = $this->get_input();` needs to know whether get_input()
            # can return tainted data, which is exactly what this records
            # when get_input()'s body is analyzed via _resolve_this_call.
            if self.return_taint is None:
                ret_expr = node.get("expr")
                if ret_expr:
                    self.return_taint = _expr_taint(ret_expr, state, self)
            return state

        # Fallthrough: recurse
        for v in node.values():
            if isinstance(v, list):
                state = self._stmts(v, state)
        return state

    def _handle_expr_stmt(self, expr, state: TaintState) -> TaintState:
        nt = _nt(expr)

        if nt == "Expr_Assign":
            new_state = self._handle_assign(expr, state)
            # Also scan the right-hand side for embedded sinks:
            # $result = $wpdb->get_results("... $id ...") -> SQL sink
            _scan_expr_for_sinks(expr.get("expr", {}), state, self.results, self)
            return new_state

        if nt == "Expr_AssignOp_Concat":
            var = expr.get("var", {})
            vname = _var_name(var)
            rhs_taint = _expr_taint(expr.get("expr", {}), state, self)
            if vname and rhs_taint:
                new_state = dict(state)
                new_state[vname] = rhs_taint
                return new_state
            return state

        # Top-level metodanrop: $wpdb->query($x)
        if nt == "Expr_MethodCall":
            _scan_expr_for_sinks(expr, state, self.results, self)
            return state

        # Top-level function call: printf($x)
        if nt == "Expr_FuncCall":
            _scan_expr_for_sinks(expr, state, self.results, self)
            return state

        if nt == "Expr_Print":
            _check_sink(expr.get("expr", {}), "output", _line(expr), state, self.results, self)
            return state

        return state

    def _handle_assign(self, expr, state: TaintState) -> TaintState:
        var = expr.get("var", {})
        vname = _var_name(var)
        if not vname:
            return state
        rhs = expr.get("expr", {})
        taint = _expr_taint(rhs, state, self)
        new_state = dict(state)
        if taint:
            new_state[vname] = taint
        else:
            new_state.pop(vname, None)
        return new_state

    def _handle_if(self, node, state: TaintState) -> TaintState:
        then_state = self._stmts(node.get("stmts", []), dict(state))
        merged = dict(state)
        for elseif in node.get("elseifs", []):
            branch = self._stmts(elseif.get("stmts", []), dict(state))
            merged = self._union(merged, branch)
        else_node = node.get("else")
        if else_node:
            else_state = self._stmts(else_node.get("stmts", []), dict(state))
            merged = self._union(merged, else_state)
        return self._union(then_state, merged)

    @staticmethod
    def _union(a: TaintState, b: TaintState) -> TaintState:
        merged = dict(a)
        for k, v in b.items():
            if k not in merged:
                merged[k] = v
        return merged


# ---------------------------------------------------------------------------
# Regex fallback
# ---------------------------------------------------------------------------


def _analyze_regex(
    code: str,
    global_context: dict[str, tuple[str, int]] | None = None,
) -> list[DataFlowResult]:
    results: list[DataFlowResult] = []
    lines = code.splitlines()
    tainted: dict[str, tuple[str, int]] = dict(global_context or {})

    san_re = re.compile(r"\b(" + "|".join(re.escape(s) for s in SANITIZERS) + r")\s*\(")
    nonce_re = re.compile(r"\b(" + "|".join(re.escape(s) for s in NONCE_FUNCTIONS) + r")\s*\(")

    for idx, line in enumerate(lines, start=1):
        san = bool(san_re.search(line))

        # Nonce context: $_POST['_wpnonce'] used as a nonce-check argument -> not taint
        if nonce_re.search(line):
            continue

        m = re.search(r"\$(\w+)\s*=\s*\$(_GET|_POST|_REQUEST|_COOKIE)\s*(\[.*?\])", line)
        if m and not san:
            tainted[m.group(1)] = (f"${m.group(2)}{m.group(3)}", idx)

        m = re.search(r'\$(\w+)\s*=\s*\$request->get_param\s*\(\s*[\'"](\w+)[\'"]\s*\)', line)
        if m and not san:
            tainted[m.group(1)] = (f"WP_REST_Request['{m.group(2)}']", idx)

        m = re.search(r"\$(\w+)\s*=\s*\$(\w+)\s*;", line)
        if m and not san:
            lhs, rhs = m.group(1), m.group(2)
            if rhs in tainted and lhs != rhs:
                tainted[lhs] = tainted[rhs]

        m = re.search(r"\$(\w+)\s*=\s*(.+)\s*;", line)
        if m and not san and "." in line:
            lhs = m.group(1)
            rhs_str = m.group(2)
            for vname, info in list(tainted.items()):
                if vname != lhs and f"${vname}" in rhs_str:
                    tainted[lhs] = info
                    break

        if san:
            m2 = re.search(r"\$(\w+)\s*=", line)
            if m2:
                tainted.pop(m2.group(1), None)

        if (
            any(kw in line for kw in ("query", "SELECT", "$wpdb", "get_results", "get_row"))
            and "prepare(" not in line
        ):
            for vname, (sg, tl) in list(tainted.items()):
                if f"${vname}" in line and not san:
                    results.append(
                        DataFlowResult(
                            var_name=vname,
                            superglobal=sg,
                            sink_type="sql",
                            sink_line=idx,
                            taint_line=tl,
                            confidence=0.85,
                        )
                    )

        if any(out in line for out in ("echo", "print", "printf", "vprintf")):
            for vname, (sg, tl) in list(tainted.items()):
                if f"${vname}" in line and not san:
                    results.append(
                        DataFlowResult(
                            var_name=vname,
                            superglobal=sg,
                            sink_type="output",
                            sink_line=idx,
                            taint_line=tl,
                            confidence=0.80,
                        )
                    )

    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


# Per-scan cache of full analyze() results, keyed by normalized source_file
# path. Without this, each of the four rule modules that need taint info
# for the SAME file (input.py, sql.py, output.py, owasp_top10.py) triggers
# its own complete AST walk -- quadrupling the cost of every file, and
# quadrupling it again for the inter-procedural $this-> resolution work
# added alongside it. DataFlowResult objects are read-only records that no
# rule module mutates, so sharing the same list across all four callers is
# safe. Cleared once per scan() call in main.py, mirroring how
# ast_engine.ASTEngine.clear_cache() is already reset per scan.
_analyze_cache: dict[tuple[str, int], list[DataFlowResult]] = {}


def clear_analyze_cache() -> None:
    """Reset the per-file analyze() result cache. Call once per scan() run."""
    _analyze_cache.clear()


def resolve_source_file(path_str: str, project=None) -> str:
    """
    Resolve a (possibly relative, possibly non-existent-as-typed) path to
    an absolute path suitable for analyze()'s source_file argument, using
    project.root when available.

    Rule modules only have the path relative to the scan root (used for
    Finding.file display), not an absolute path. Without this helper, that
    relative path fails os.path.isfile() (it's relative to the current
    working directory, not the scan root), forcing analyze() to write a
    fresh temp file and spawn a new PHP subprocess on every call -- even
    though main.py._scan_file() already pre-warmed ASTEngine's cache under
    the correct ABSOLUTE path for this exact file. Reconstructing that
    absolute path here lets analyze() hit the pre-warmed cache directly,
    with no ambiguity (unlike the old suffix-matching fallback this
    replaces, which could accidentally match an unrelated file -- see the
    comment in analyze() itself for the collision this caused).

    Falls back to returning path_str unchanged when no project/root is
    available (e.g. a unit test calling a rule function directly with a
    synthetic path and no ProjectIndex) -- analyze() then correctly falls
    through to parsing code_input directly.
    """
    if project is not None and getattr(project, "root", None) is not None:
        try:
            return str(project.root / path_str)
        except (TypeError, ValueError):
            pass
    return path_str


def analyze(
    code_input: str,
    global_context: dict[str, tuple[str, int]] | None = None,
    source_file: str = "",
    project=None,
) -> list[DataFlowResult]:
    """
    `project` (a ProjectIndex, optional) enables inter-procedural taint
    resolution for $this->method() calls within the same class -- see
    ASTAnalyzer's class docstring. Callers that don't have a ProjectIndex
    handy (or are analyzing a code snippet with no real file) simply omit
    it and get the previous, intra-procedural-only behavior.

    Results are cached per (normalized source_file, content hash) for the
    lifetime of one scan() run (see _analyze_cache above) -- calling
    analyze() four times for the same file (once per rule module) only
    walks its AST once. The content hash is included, not just the file
    path, because the same nominal path (e.g. a test fixture reusing
    "x.php" across many test cases with different code each time) must
    never return a stale result from a previous call with different code.
    """
    norm_path = source_file.replace("\\", "/") if source_file else ""
    cache_key = (norm_path, hash(code_input)) if norm_path else None
    if cache_key is not None and cache_key in _analyze_cache:
        return _analyze_cache[cache_key]

    ast = None
    tmp_path = None

    try:
        if source_file and os.path.isfile(source_file):
            # Direct hit: source_file resolves to a real file on disk (the
            # common case during a real scan, where main.py._scan_file
            # already pre-warmed ASTEngine's in-memory cache under this
            # exact absolute path).
            ast = _engine.get_ast(source_file)
        elif code_input:
            # source_file is empty, or doesn't resolve relative to the
            # current working directory (e.g. a relative path like
            # "src/file.php" checked outside the scan root, or a synthetic
            # path used in a unit test). Always fall through to writing
            # code_input to a temp file and parsing that directly.
            #
            # An earlier version of this branch tried to be clever here:
            # it searched ASTEngine's in-memory cache for any entry whose
            # path happened to end with the same suffix as source_file,
            # to reuse an already-parsed AST instead of spawning a new
            # subprocess. That is unsafe -- a synthetic/non-existent path
            # like "x.php" can accidentally suffix-match a COMPLETELY
            # UNRELATED file left over from a previous call in the same
            # process (e.g. two unit tests that both nominally use
            # Path("x.php") but with different code), silently analyzing
            # the wrong content. The _analyze_cache added below (keyed on
            # a hash of the actual code_input, not a guessed path match)
            # delivers the same cross-call performance win without that
            # correctness hazard, so this fallback no longer needs to
            # gamble on a suffix match -- it just parses what it was
            # actually given.
            with tempfile.NamedTemporaryFile(
                suffix=".php", mode="w", encoding="utf-8", delete=False
            ) as f:
                f.write(code_input)
                tmp_path = f.name
            ast = _engine.get_ast(tmp_path)
    except Exception:
        ast = None
    finally:
        if tmp_path:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)

    if ast is not None:
        # AST-based analysis via nikic/php-parser — high precision;
        # a cache hit here costs effectively 0 ms of extra time.
        analyzer = ASTAnalyzer(project=project)
        result = analyzer.analyze(ast)
        if cache_key is not None:
            _analyze_cache[cache_key] = result
        return result

    # Regex fallback: PHP is not available, or the file is too large
    # for the parser to handle within the timeout.
    result = _analyze_regex(code_input, global_context)
    if cache_key is not None:
        _analyze_cache[cache_key] = result
    return result
