# analysis/taint_tracker.py - Moteur de taint analysis (intra + inter-procedural)
#
# Vue d'ensemble
# --------------
# 1. Les fonctions/methodes du fichier sont "hoistees" : chaque corps est analyse
#    avec des parametres symboliques (TaintLabel source_type="param"). On en
#    deduit un FunctionSummary : parametres atteignant un sink (ParamSink) et
#    parametres propages vers le retour. Les sinks atteints par de vraies
#    sources ($_GET...) a l'interieur du corps produisent directement un Finding.
# 2. Le code global est analyse ; a chaque appel d'une fonction resumee, les
#    taints reels des arguments sont substitues aux parametres symboliques :
#    finding au niveau du sink (dans la fonction appelee) avec la trace complete,
#    et retour taint si la fonction propage.
# 3. Les closures sont analysees en ligne (hooks WordPress, callbacks).
# 4. Les conditions sont analysees comme gardes : is_numeric($x), in_array($x, $ok),
#    preg_match('/^\d+$/', $x), $x === 'lit' ... neutralisent $x dans la branche
#    then ; si la branche then se termine (exit/return/throw), la forme negative
#    neutralise $x pour la suite du bloc.
#
# Les categories de vulnerabilite sont portees par chaque label (voir
# taint_state.py), si bien que htmlspecialchars($a) . $b reste dangereux via $b.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

from analysis.taint_state import TaintLabel, TaintFact, TraceStep, TaintState
from analysis.cross_file_context import FunctionSummary, ParamSink, CrossFileContext
from report.finding import Finding
from config.schema import Severity, Confidence, SinkSpec, FilterInfo

if TYPE_CHECKING:
    from config.loader import RulesConfig


CALL_NODE_TYPES = frozenset({
    "function_call_expression",
    "member_call_expression",
    "nullsafe_member_call_expression",
    "scoped_call_expression",
    "object_creation_expression",
})

INCLUDE_NODE_TYPES = frozenset({
    "include_expression", "include_once_expression",
    "require_expression", "require_once_expression",
})

CLOSURE_NODE_TYPES = frozenset({"anonymous_function", "arrow_function"})

LITERAL_NODE_TYPES = frozenset({
    "string", "integer", "float", "boolean", "null", "nowdoc", "nowdoc_string",
    "name", "qualified_name", "string_content", "comment", "text",
    "class_constant_access_expression", "relative_scope",
})

CLASS_LIKE_TYPES = frozenset({
    "class_declaration", "trait_declaration", "enum_declaration", "interface_declaration",
})

ARITHMETIC_OPS = frozenset({"+", "-", "*", "/", "%", "**", "<<", ">>", "&", "|", "^",
                            "==", "!=", "===", "!==", "<", ">", "<=", ">=", "<=>",
                            "&&", "||", "and", "or", "xor", "instanceof"})

FALSY_LITERALS = frozenset({"false", "0", "null", "''", '""', "FALSE", "NULL", "False", "None"})
TRUTHY_LITERALS = frozenset({"true", "1", "TRUE", "True"})

LOW_CONF_SOURCE_TYPES = frozenset({"environment"})

_WS_RE = re.compile(r"\s+")


def _last_segment(name: str) -> str:
    return name.strip().strip("\\").split("\\")[-1]


@dataclass
class CallInfo:
    """Description normalisee d'un appel (fonction, methode, statique, new, dynamique)."""
    node: object
    kind: str                      # function | method | static | new | dynamic
    short_name: str = ""           # nom sans classe ni namespace
    display_name: str = ""         # nom affiche dans le finding
    class_name: Optional[str] = None   # static / new
    obj_node: Optional[object] = None   # method
    dynamic_node: Optional[object] = None
    args: list = field(default_factory=list)


class TaintTracker:
    """Moteur de taint analysis sur l'AST tree-sitter PHP d'un fichier.

    Parametres
    ----------
    source_code, tree, file_path : fichier a analyser.
    rules          : RulesConfig (sources, sinks, filtres, validateurs...).
    global_context : CrossFileContext partage (resumes de fonctions, includes).
    """

    def __init__(
        self,
        source_code: str,
        tree,
        file_path: str,
        rules: "RulesConfig",
        global_context: Optional["CrossFileContext"] = None,
    ):
        self.source = source_code
        self.source_bytes = source_code.encode("utf-8")
        self.lines = source_code.splitlines()
        self.tree = tree
        self.file_path = file_path
        self.rules = rules
        self.ctx: CrossFileContext = global_context if global_context is not None else CrossFileContext()
        self.all_categories: frozenset = frozenset(rules.taint_categories)

        self.global_state = TaintState()
        self.state: TaintState = self.global_state
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()

        # Contexte courant
        self.current_function: Optional[FunctionSummary] = None
        self.current_class: Optional[str] = None
        self.privilege_depth = 0
        self.class_states: dict[str, TaintState] = {}
        self._class_props_changed = False
        self._uses_globals = False
        self._closure_depth = 0

        # Heriter le taint des fichiers inclus
        if global_context is not None:
            for var, fact in global_context.get_included_taint(file_path).items():
                self.global_state.set_taint(var, fact)

    # ==================================================================
    # Point d'entree
    # ==================================================================

    def analyze(self, summaries_only: bool = False) -> list[Finding]:
        """Analyse le fichier. summaries_only=True ne calcule que les resumes de fonctions."""
        root = self.tree.root_node
        functions = self._collect_functions(root)

        # Passe 1 : fonctions (resumes + findings directs)
        self._analyze_functions(functions)
        if summaries_only:
            return self.findings

        # Passe 2 : code global (utilise les resumes)
        self.state = self.global_state
        self._walk_body(root)

        # Passe 3 : re-analyser les fonctions si elles dependent de l'etat global
        # ou de proprietes de classe decouvertes en passe 1.
        if functions and (self._uses_globals or self._class_props_changed):
            self._class_props_changed = False
            self._analyze_functions(functions)

        # Exporter le taint global (labels reels uniquement)
        self.ctx.exported_taint[self.file_path] = {
            k: v for k, v in self.global_state.variables.items() if v.real_labels()
        }
        return self.findings

    # ==================================================================
    # Fonctions & resumes
    # ==================================================================

    def _collect_functions(self, root) -> list[tuple]:
        """Liste (node, class_name) de toutes les fonctions/methodes avec corps."""
        out: list[tuple] = []

        def rec(node, cls):
            for c in node.children:
                if c.type == "function_definition":
                    out.append((c, None))
                    rec(c, None)
                elif c.type == "method_declaration":
                    out.append((c, cls))
                    rec(c, cls)
                elif c.type in CLASS_LIKE_TYPES:
                    name_node = c.child_by_field_name("name")
                    rec(c, self._text(name_node) if name_node else None)
                elif c.type == "anonymous_class":
                    rec(c, None)
                else:
                    rec(c, cls)

        rec(root, None)
        return out

    def _analyze_functions(self, functions: list[tuple]):
        for node, cls in functions:
            self._analyze_function(node, cls)
        if self._class_props_changed:
            # Les proprietes taintees par une methode doivent etre visibles des autres.
            self._class_props_changed = False
            for node, cls in functions:
                if cls is not None:
                    self._analyze_function(node, cls)

    def _analyze_function(self, node, class_name: Optional[str]):
        body = node.child_by_field_name("body")
        if body is None:
            return  # abstract / interface
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return
        name = self._text(name_node)
        params = self._parameters(node)
        is_method = node.type == "method_declaration"
        modifiers = {c.type for c in node.children}
        summary = FunctionSummary(
            name=name,
            file_path=self.file_path,
            class_name=class_name,
            params=[p[0] for p in params],
            start_line=node.start_point[0] + 1,
            is_method=is_method,
            is_static="static_modifier" in modifiers,
        )

        saved = (self.state, self.current_function, self.current_class, self.privilege_depth)
        self.state = TaintState()
        self.current_function = summary
        self.current_class = class_name
        self.privilege_depth = 0
        qualified = summary.qualified_name

        for idx, (pname, ptype) in enumerate(params):
            label = TaintLabel(
                source_type="param",
                source_var=pname,
                source_file=self.file_path,
                source_line=node.start_point[0] + 1,
                vuln_categories=self.all_categories,
                param_index=idx,
            )
            fact = TaintFact(
                labels=frozenset({label}),
                trace=[TraceStep(
                    file=self.file_path,
                    line=node.start_point[0] + 1,
                    description=f"Parameter {pname} of {qualified}()",
                    snippet=self._line_snippet(node),
                )],
            )
            # Un parametre type "Request" est une source reelle (frameworks)
            if ptype and ptype in self.rules.request_types:
                fact = self._source_fact(pname, node, "user_input")
            self.state.set_taint(pname, fact)
            if ptype:
                self.state.set_type(pname, ptype)
        if class_name:
            self.state.set_type("$this", class_name)

        try:
            self._walk_body(body)
        finally:
            self.state, self.current_function, self.current_class, self.privilege_depth = saved

        self.ctx.register_function_summary(self.file_path, name, summary)

    def _parameters(self, func_node) -> list[tuple[str, Optional[str]]]:
        params: list[tuple[str, Optional[str]]] = []
        params_node = func_node.child_by_field_name("parameters")
        if params_node is None:
            return params
        for child in params_node.named_children:
            if child.type not in ("simple_parameter", "variadic_parameter", "property_promotion_parameter"):
                continue
            name_node = child.child_by_field_name("name")
            if name_node is None:
                continue
            type_node = child.child_by_field_name("type")
            ptype = None
            if type_node is not None:
                ptype = _last_segment(self._text(type_node).lstrip("?").split("|")[0])
            params.append((self._text(name_node), ptype))
        return params

    # ==================================================================
    # Parcours des statements
    # ==================================================================

    def _walk(self, node):
        handler = self._handlers.get(node.type)
        if handler is not None:
            handler(self, node)
        elif node.type in CALL_NODE_TYPES or node.type.endswith("_expression") or node.type in CLOSURE_NODE_TYPES:
            self._visit_expr(node)
        else:
            for child in node.named_children:
                self._walk(child)

    def _walk_body(self, body):
        """Parcourt un corps : bloc {}, bloc ':' ... 'end*', ou statement unique."""
        if body is None:
            return
        saved_priv = self.privilege_depth
        if body.type in ("compound_statement", "colon_block", "program", "declaration_list"):
            for child in body.named_children:
                self._walk(child)
        else:
            self._walk(body)
        self.privilege_depth = saved_priv

    def _walk_children(self, node):
        for child in node.named_children:
            self._walk(child)

    def _handle_noop(self, node):
        """Definitions de fonctions/classes : analysees separement (hoisting)."""
        return

    def _handle_expression_statement(self, node):
        # <?= expr ?> : echo implicite
        is_short_echo = self._preceded_by_short_echo_tag(node)
        for child in node.named_children:
            if is_short_echo:
                self._check_output_sink(child, "echo_statement", "echo")
            self._visit_expr(child)

    def _preceded_by_short_echo_tag(self, node) -> bool:
        """<?= expr ?> : le tag est le dernier enfant du text_interpolation precedent."""
        prev = node.prev_sibling
        if prev is None:
            return False
        if prev.type == "php_tag":
            return self._text(prev).strip() == "<?="
        if prev.type == "text_interpolation" and prev.children:
            last = prev.children[-1]
            return last.type == "php_tag" and self._text(last).strip() == "<?="
        return False

    def _handle_echo(self, node):
        for child in node.named_children:
            self._check_output_sink(child, "echo_statement", "echo")
            self._visit_expr(child)

    def _handle_print(self, node):
        for child in node.named_children:
            self._check_output_sink(child, "print_intrinsic", "print")
            self._visit_expr(child)

    def _handle_exit(self, node):
        for child in node.named_children:
            self._check_output_sink(child, "exit_statement", "exit")
            self._visit_expr(child)

    def _check_output_sink(self, expr, node_type: str, sink_name: str):
        rule = self.rules.get_node_type_vuln(node_type)
        if rule is None:
            return
        taint = self._evaluate_taint(expr)
        if taint is not None and self._relevant(taint, rule.vuln_type):
            self._record_finding(rule.vuln_type, expr.parent if expr.parent else expr,
                                 sink_name, taint)

    def _handle_shell_command(self, node):
        rule = self.rules.get_node_type_vuln("shell_command_expression")
        taint = self._eval_interpolated(node, "Shell backtick interpolation")
        if rule is not None and taint is not None and self._relevant(taint, rule.vuln_type):
            self._record_finding(rule.vuln_type, node, "`backticks`", taint)
        for child in node.named_children:
            self._visit_expr(child)

    def _handle_include(self, node):
        rule = self.rules.get_node_type_vuln(node.type)
        expr = node.named_children[0] if node.named_children else None
        if expr is None:
            return
        if rule is not None:
            taint = self._evaluate_taint(expr)
            if taint is not None and self._relevant(taint, rule.vuln_type):
                keyword = node.type.replace("_expression", "")
                self._record_finding(rule.vuln_type, node, keyword, taint)
        self._visit_expr(expr)

    def _handle_return(self, node):
        if not node.named_children:
            return
        expr = node.named_children[0]
        taint = self._evaluate_taint(expr)
        self._visit_expr(expr)
        if taint is not None and taint.has_labels and self.current_function is not None and self._closure_depth == 0:
            fact = taint.derive(f"Returned from {self.current_function.qualified_name}()",
                                file=self.file_path, line=node.start_point[0] + 1,
                                snippet=self._line_snippet(node))
            self.current_function.return_fact = TaintFact.merge(self.current_function.return_fact, fact)

    def _handle_global(self, node):
        self._uses_globals = True
        for child in node.named_children:
            if child.type != "variable_name":
                continue
            key = self._key(child)
            fact = self.global_state.get_taint(key)
            if fact is not None:
                self.state.set_taint(key, fact.derive(f"Imported via global {key}",
                                                      file=self.file_path, line=node.start_point[0] + 1))
            t = self.global_state.get_type(key)
            if t:
                self.state.set_type(key, t)

    def _handle_unset(self, node):
        for child in node.named_children:
            self.state.remove_taint(self._key(child))

    # --- Structures de controle ---

    def _handle_if(self, node):
        cond = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        alts = [c for c in node.children if c.type in ("else_if_clause", "else_clause")]
        self._handle_branching(cond, body, alts)

    def _handle_branching(self, cond, body, alts: list) -> bool:
        """Analyse if/elseif/else avec gardes. Retourne True si toutes les branches terminent."""
        then_guards: dict = {}
        else_guards: dict = {}
        priv_then = False
        priv_else = False
        if cond is not None:
            self._visit_expr(cond)
            then_guards, else_guards = self._condition_guards(cond)
            priv_then, priv_else = self._privilege_guards(cond)

        pre = self.state

        # Branche then
        self.state = pre.clone()
        self._apply_guards(then_guards)
        if priv_then:
            self.privilege_depth += 1
        self._walk_body(body)
        if priv_then:
            self.privilege_depth -= 1
        then_state = self.state
        then_term = self._terminates(body)

        # Branche else / elseif
        self.state = pre.clone()
        self._apply_guards(else_guards)
        else_term = False
        if alts:
            first = alts[0]
            if first.type == "else_if_clause":
                else_term = self._handle_branching(
                    first.child_by_field_name("condition"),
                    first.child_by_field_name("body"),
                    alts[1:],
                )
            else:
                else_body = first.child_by_field_name("body")
                if else_body is None and first.named_children:
                    else_body = first.named_children[0]
                self._walk_body(else_body)
                else_term = self._terminates(else_body)
        else_state = self.state

        # Jonction
        if then_term and not else_term:
            self.state = else_state
            if priv_else:
                # if (!current_user_can()) exit;  -> la suite est privilegiee
                self.privilege_depth += 1
        elif else_term and not then_term:
            self.state = then_state
            if priv_then:
                self.privilege_depth += 1
        else:
            self.state = then_state.merge(else_state)
        return then_term and else_term

    def _handle_while(self, node):
        cond = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        if cond is not None:
            self._visit_expr(cond)
        self._loop_body(body)

    def _handle_do(self, node):
        body = node.child_by_field_name("body")
        cond = node.child_by_field_name("condition")
        self._loop_body(body)
        if cond is not None:
            self._visit_expr(cond)

    def _handle_for(self, node):
        for fname in ("initializer", "condition", "update"):
            n = node.child_by_field_name(fname)
            if n is not None:
                self._visit_expr(n)
        # tree-sitter-php expose parfois ces expressions comme enfants nommes sans champ
        body = node.child_by_field_name("body")
        if body is None:
            for c in node.named_children:
                if c.type in ("compound_statement", "colon_block"):
                    body = c
                elif c.type.endswith("_expression") or c.type in ("sequence_expression", "variable_name"):
                    self._visit_expr(c)
        self._loop_body(body)

    def _loop_body(self, body):
        pre = self.state.clone()
        self._walk_body(body)
        self._walk_body(body)  # 2eme iteration : taint loop-carried
        self.state = pre.merge(self.state)

    def _handle_foreach(self, node):
        children = list(node.named_children)
        if not children:
            return
        source_node = children[0]
        source_taint = self._evaluate_taint(source_node)
        self._visit_expr(source_node)
        body = node.child_by_field_name("body")
        if body is None:
            for c in children[1:]:
                if c.type in ("compound_statement", "colon_block"):
                    body = c

        # Variables d'iteration
        iter_nodes = [c for c in children[1:] if c is not body]
        for it in iter_nodes:
            self._assign_foreach_target(it, source_taint, node)

        self._loop_body(body)

    def _assign_foreach_target(self, target, source_taint: Optional[TaintFact], node):
        line = node.start_point[0] + 1
        if target.type == "pair":
            parts = list(target.named_children)
            if len(parts) >= 2:
                self._assign_foreach_target(parts[0], source_taint, node)
                self._assign_foreach_target(parts[1], source_taint, node)
            return
        if target.type == "by_ref":
            inner = target.named_children[0] if target.named_children else None
            if inner is not None:
                self._assign_foreach_target(inner, source_taint, node)
            return
        if target.type == "list_literal":
            for el in target.named_children:
                self._assign_foreach_target(el, source_taint, node)
            return
        key = self._key(target)
        if not key:
            return
        if source_taint is not None and source_taint.has_labels:
            self.state.set_taint(key, source_taint.derive(
                f"Foreach iteration into {key}", file=self.file_path, line=line,
                snippet=self._line_snippet(node)))
        else:
            self.state.remove_taint(key)

    def _handle_switch(self, node):
        cond = node.child_by_field_name("condition")
        subject_key = None
        if cond is not None:
            self._visit_expr(cond)
            subject_key = self._guard_target(cond)
        body = node.child_by_field_name("body")
        if body is None:
            return
        pre = self.state
        states = [pre]
        for case in body.named_children:
            if case.type not in ("case_statement", "default_statement"):
                continue
            self.state = pre.clone()
            value = case.child_by_field_name("value")
            if subject_key and value is not None and self._is_literal(value):
                self._apply_guard(subject_key, self.all_categories, "equals literal", Confidence.HIGH)
            for stmt in case.named_children:
                if stmt is value:
                    continue
                self._walk(stmt)
            states.append(self.state)
        merged = states[0]
        for s in states[1:]:
            merged = merged.merge(s)
        self.state = merged

    def _handle_try(self, node):
        body = node.child_by_field_name("body")
        pre = self.state.clone()
        self._walk_body(body)
        states = [self.state]
        finally_body = None
        for clause in node.named_children:
            if clause.type == "catch_clause":
                self.state = pre.clone()
                var = clause.child_by_field_name("name")
                typ = clause.child_by_field_name("type")
                if var is not None and typ is not None:
                    self.state.set_type(self._key(var), _last_segment(self._text(typ).split("|")[0]))
                self._walk_body(clause.child_by_field_name("body"))
                states.append(self.state)
            elif clause.type == "finally_clause":
                finally_body = clause.child_by_field_name("body")
        merged = states[0]
        for s in states[1:]:
            merged = merged.merge(s)
        self.state = merged
        if finally_body is not None:
            self._walk_body(finally_body)

    # ==================================================================
    # Visite des expressions (sinks, effets de bord)
    # ==================================================================

    def _visit_expr(self, node):
        if node is None:
            return
        t = node.type
        if t in LITERAL_NODE_TYPES:
            return
        if t in CALL_NODE_TYPES:
            self._handle_call(node)
            return
        if t in CLOSURE_NODE_TYPES:
            self._handle_closure(node)
            return
        if t == "assignment_expression":
            self._handle_assignment(node)
            return
        if t == "augmented_assignment_expression":
            self._handle_augmented_assignment(node)
            return
        if t == "reference_assignment_expression":
            self._handle_reference_assignment(node)
            return
        if t in INCLUDE_NODE_TYPES:
            self._handle_include(node)
            return
        if t == "print_intrinsic":
            self._handle_print(node)
            return
        if t == "shell_command_expression":
            self._handle_shell_command(node)
            return
        if t == "anonymous_class":
            return  # methodes analysees par hoisting
        for child in node.named_children:
            self._visit_expr(child)

    # --- Assignations ---

    def _handle_assignment(self, node):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        rhs = self._evaluate_taint(right)
        self._visit_expr(right)
        line = node.start_point[0] + 1
        snippet = self._line_snippet(node)

        if left.type == "list_literal":
            self._assign_list(left, rhs, line, snippet)
            return

        key = self._key(left)
        if not key:
            return
        self.state.set_type(key, self._class_of_expr(right))

        if rhs is not None and rhs.has_labels:
            self._store(key, rhs.derive(f"Assigned to {key}", file=self.file_path, line=line, snippet=snippet))
        else:
            self.state.remove_taint(key)

        # $arr['k'] = tainted  ->  $arr est (partiellement) tainted
        if left.type == "subscript_expression" and rhs is not None and rhs.has_labels:
            base = left.named_children[0] if left.named_children else None
            if base is not None:
                base_key = self._key(base)
                if base_key and not self.rules.is_source(base_key):
                    self._store(base_key, TaintFact.merge(self.state.get_taint(base_key), rhs))

    def _assign_list(self, list_node, rhs: Optional[TaintFact], line: int, snippet: str):
        for el in list_node.named_children:
            target = el
            if el.type == "pair":
                parts = el.named_children
                target = parts[-1] if parts else None
            if target is None:
                continue
            if target.type == "list_literal":
                self._assign_list(target, rhs, line, snippet)
                continue
            if target.type == "by_ref" and target.named_children:
                target = target.named_children[0]
            key = self._key(target)
            if not key:
                continue
            if rhs is not None and rhs.has_labels:
                self._store(key, rhs.derive(f"Destructured into {key}", file=self.file_path, line=line, snippet=snippet))
            else:
                self.state.remove_taint(key)

    def _handle_augmented_assignment(self, node):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        op_node = node.child_by_field_name("operator")
        op = self._text(op_node) if op_node is not None else ".="
        rhs = self._evaluate_taint(right)
        self._visit_expr(right)
        key = self._key(left)
        if not key:
            return
        if op not in (".=", "??="):
            return  # +=, -=, ... : resultat numerique
        existing = self.state.get_taint(key)
        merged = TaintFact.merge(existing, rhs)
        if merged is not None and merged.has_labels:
            self._store(key, merged.derive(f"Appended to {key}", file=self.file_path,
                                           line=node.start_point[0] + 1, snippet=self._line_snippet(node)))

    def _handle_reference_assignment(self, node):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        rhs = self._evaluate_taint(right)
        key = self._key(left)
        if key and rhs is not None and rhs.has_labels:
            self._store(key, rhs.derive(f"Referenced as {key}", file=self.file_path, line=node.start_point[0] + 1))

    def _store(self, key: str, fact: TaintFact):
        self.state.set_taint(key, fact)
        if self.current_class is not None and (key.startswith("$this->") or key.startswith("self::") or key.startswith("static::")):
            real = fact.real_labels()
            if real:
                cs = self.class_states.setdefault(self.current_class, TaintState())
                prev = cs.get_taint(key)
                new = TaintFact(labels=real, filters_applied=dict(fact.filters_applied), trace=list(fact.trace))
                if prev is None or prev.labels != (prev.labels | real):
                    cs.set_taint(key, TaintFact.merge(prev, new))
                    self._class_props_changed = True

    # --- Closures ---

    def _handle_closure(self, node):
        saved_state = self.state
        if node.type == "arrow_function":
            self.state = saved_state.clone()
        else:
            self.state = TaintState()
            if saved_state.get_type("$this"):
                self.state.set_type("$this", saved_state.get_type("$this"))
            use_clause = next((c for c in node.named_children if c.type == "anonymous_function_use_clause"), None)
            if use_clause is not None:
                for v in use_clause.named_children:
                    target = v.named_children[0] if v.type == "by_ref" and v.named_children else v
                    key = self._key(target)
                    fact = saved_state.get_taint(key)
                    if fact is not None:
                        self.state.set_taint(key, fact)
                    if saved_state.get_type(key):
                        self.state.set_type(key, saved_state.get_type(key))
        for pname, ptype in self._parameters(node):
            if ptype:
                self.state.set_type(pname, ptype)
                if ptype in self.rules.request_types:
                    self.state.set_taint(pname, self._source_fact(pname, node, "user_input"))
        self._closure_depth += 1
        body = node.child_by_field_name("body")
        try:
            if body is not None:
                if body.type == "compound_statement":
                    self._walk_body(body)
                else:
                    self._visit_expr(body)
        finally:
            self._closure_depth -= 1
            self.state = saved_state

    # ==================================================================
    # Appels : sinks, resumes
    # ==================================================================

    def _call_info(self, node) -> Optional[CallInfo]:
        t = node.type
        info = CallInfo(node=node, kind="function")
        if t == "function_call_expression":
            fn = node.child_by_field_name("function")
            if fn is None:
                return None
            if fn.type in ("name", "qualified_name"):
                info.display_name = self._text(fn)
                info.short_name = _last_segment(info.display_name)
            else:
                info.kind = "dynamic"
                info.dynamic_node = fn
                info.display_name = self._text(fn)
                info.short_name = ""
        elif t in ("member_call_expression", "nullsafe_member_call_expression"):
            info.kind = "method"
            info.obj_node = node.child_by_field_name("object")
            name_node = node.child_by_field_name("name")
            if name_node is None:
                return None
            if name_node.type == "name":
                info.short_name = self._text(name_node)
                info.display_name = f"{self._short_obj_text(info.obj_node)}->{info.short_name}"
            else:
                info.kind = "dynamic"
                info.dynamic_node = name_node
                info.display_name = self._text(node).split("(")[0]
        elif t == "scoped_call_expression":
            info.kind = "static"
            scope = node.child_by_field_name("scope")
            name_node = node.child_by_field_name("name")
            if name_node is None:
                return None
            if scope is not None:
                scope_text = self._text(scope)
                if scope.type == "relative_scope":
                    info.class_name = self.current_class if scope_text in ("self", "static") else None
                    if scope_text == "parent":
                        info.class_name = None
                elif scope.type in ("name", "qualified_name"):
                    info.class_name = _last_segment(scope_text)
                else:
                    info.class_name = self.state.get_type(self._key(scope))
                info.obj_node = scope
            if name_node.type == "name":
                info.short_name = self._text(name_node)
                info.display_name = f"{self._text(scope) if scope is not None else ''}::{info.short_name}"
            else:
                info.kind = "dynamic"
                info.dynamic_node = name_node
                info.display_name = self._text(node).split("(")[0]
        elif t == "object_creation_expression":
            info.kind = "new"
            for c in node.named_children:
                if c.type in ("name", "qualified_name"):
                    info.class_name = _last_segment(self._text(c))
                    info.short_name = info.class_name
                    info.display_name = "new " + info.class_name
                    break
                if c.type in ("variable_name", "member_access_expression", "subscript_expression"):
                    info.kind = "dynamic"
                    info.dynamic_node = c
                    info.display_name = "new " + self._text(c)
                    break
                if c.type == "anonymous_class":
                    info.display_name = "new class"
                    break
        else:
            return None
        info.args = self._args(node)
        return info

    def _args(self, node) -> list:
        args_node = node.child_by_field_name("arguments")
        if args_node is None:
            args_node = next((c for c in node.named_children if c.type == "arguments"), None)
        if args_node is None:
            return []
        return [c for c in args_node.named_children if c.type != "comment"]

    def _handle_call(self, node):
        """Cote statement : sinks, resumes (param -> sink), effets par reference."""
        info = self._call_info(node)
        if info is None:
            for child in node.named_children:
                self._visit_expr(child)
            return
        if info.short_name:
            self.ctx.register_call(info.short_name)

        # Appel dynamique : $fn($x), $obj->$m(), new $cls  -> code_injection si le nom est tainted
        if info.kind == "dynamic" and info.dynamic_node is not None:
            t = self._evaluate_taint(info.dynamic_node)
            if t is not None and self._relevant(t, "code_injection"):
                self._record_finding("code_injection", node, f"dynamic call {info.display_name}", t)

        # Sinks
        for spec in self._sinks_for(info):
            self._check_sink(spec, info, node)

        # Resume : parametres atteignant des sinks dans la fonction appelee
        summary = self._resolve_callee(info)
        if summary is not None and summary.param_sinks:
            self._apply_summary_sinks(summary, info, node)

        self._apply_ref_outputs(info)

        # Sous-expressions (appels imbriques, closures, assignations inline)
        for arg in info.args:
            self._visit_expr(arg)
        if info.obj_node is not None:
            self._visit_expr(info.obj_node)
        if info.dynamic_node is not None:
            self._visit_expr(info.dynamic_node)

    def _sinks_for(self, info: CallInfo) -> list[SinkSpec]:
        if info.kind == "function":
            specs = list(self.rules.get_function_sinks(info.short_name))
        elif info.kind == "method":
            specs = []
            for cls in self._class_hints(info.obj_node, info.short_name):
                specs.extend(self.rules.get_class_method_sinks(cls, info.short_name))
            if not specs:
                specs.extend(self.rules.get_method_sinks(info.short_name))
        elif info.kind == "static":
            specs = []
            if info.class_name:
                specs.extend(self.rules.get_class_method_sinks(info.class_name, info.short_name))
            if not specs:
                specs.extend(self.rules.get_method_sinks(info.short_name))
        elif info.kind == "new" and info.class_name:
            specs = list(self.rules.get_new_sinks(info.class_name))
        else:
            specs = []
        # Un seul spec par type de vuln ; path_traversal vs ssrf departage au check
        seen: set[str] = set()
        out: list[SinkSpec] = []
        for s in specs:
            if s.vuln_type not in seen:
                seen.add(s.vuln_type)
                out.append(s)
        return out

    def _check_sink(self, spec: SinkSpec, info: CallInfo, node):
        if spec.vuln_type not in self.rules.vulnerabilities:
            return
        args = info.args
        if spec.max_args is not None and len(args) > spec.max_args:
            return
        if spec.when_arg is not None:
            idx, regex = spec.when_arg
            if idx >= len(args) or not re.search(regex, self._text(args[idx])):
                return
        if spec.safe_if_arg is not None:
            idx, regex = spec.safe_if_arg
            if idx < len(args) and re.search(regex, self._text(args[idx])):
                return
        indices = spec.args if spec.args is not None else list(range(len(args)))
        combined: Optional[TaintFact] = None
        first_arg = None
        for i in indices:
            if i < 0:
                i = len(args) + i
            if i >= len(args):
                continue
            arg = args[i]
            taint = self._evaluate_taint(arg)
            if taint is None or not self._relevant(taint, spec.vuln_type):
                continue
            # header() : open redirect seulement pour Location/Refresh
            if info.kind == "function" and info.short_name == "header" and spec.vuln_type == "open_redirect":
                if not self._is_redirect_header(arg, taint):
                    continue
            if first_arg is None:
                first_arg = arg
            combined = TaintFact.merge(combined, taint)
        if combined is None or first_arg is None:
            return
        vuln_type = spec.vuln_type
        # path_traversal vs ssrf pour file_get_contents/fopen/copy...
        if vuln_type in ("path_traversal", "ssrf"):
            vuln_type = self._disambiguate_path_or_url(info, first_arg, combined, vuln_type)
            if vuln_type not in self.rules.vulnerabilities:
                return
        evidence = info.kind != "method" or spec.kind != "any_method" or bool(self._class_hints(info.obj_node, info.short_name))
        conf = spec.confidence if evidence else min(spec.confidence, Confidence.MEDIUM)
        self._record_finding(vuln_type, node, info.display_name, combined, sink_conf=conf)

    def _is_redirect_header(self, arg, taint: TaintFact) -> bool:
        lead = self._leading_literal(arg)
        if lead:
            return lead.lower().lstrip().startswith(("location", "refresh"))
        # header($h) : chercher "location" dans la construction de $h
        for step in taint.trace:
            if "location" in (step.snippet or "").lower():
                return True
        return "location" in self._line_snippet(arg).lower()

    def _disambiguate_path_or_url(self, info: CallInfo, arg, taint: TaintFact, default: str) -> str:
        names = self._both_path_and_url(info)
        if not names:
            return default
        hint = self.rules.url_hint_pattern
        lead = self._leading_literal(arg)
        if lead and re.match(r"^[a-z][a-z0-9+.-]*://", lead.strip().lower()):
            return "ssrf"
        if lead and (lead.startswith("/") or lead.startswith(".") or "\\" in lead or lead.lower().startswith(("c:", "d:"))):
            return "path_traversal"
        texts = [self._text(arg)] + [l.source_var for l in taint.labels] + [s.snippet or "" for s in taint.trace]
        if hint is not None and any(hint.search(t) for t in texts):
            return "ssrf"
        return "path_traversal"

    def _both_path_and_url(self, info: CallInfo) -> bool:
        if info.kind != "function":
            return False
        vulns = {s.vuln_type for s in self.rules.get_function_sinks(info.short_name)}
        return {"path_traversal", "ssrf"} <= vulns

    def _resolve_callee(self, info: CallInfo) -> Optional[FunctionSummary]:
        if not info.short_name:
            return None
        if info.kind == "function":
            return self.ctx.get_function_summary(info.short_name, file_hint=self.file_path, want_method=False)
        if info.kind == "method":
            hints = self._class_hints(info.obj_node, info.short_name)
            return self.ctx.get_function_summary(info.short_name, class_hint=hints[0] if hints else None,
                                                 file_hint=self.file_path, want_method=True)
        if info.kind == "static":
            return self.ctx.get_function_summary(info.short_name, class_hint=info.class_name,
                                                 file_hint=self.file_path, want_method=True)
        if info.kind == "new" and info.class_name:
            return self.ctx.get_function_summary("__construct", class_hint=info.class_name,
                                                 file_hint=self.file_path, want_method=True)
        return None

    def _apply_summary_sinks(self, summary: FunctionSummary, info: CallInfo, node):
        if self.current_function is summary:
            return  # recursion directe
        args = info.args
        line = node.start_point[0] + 1
        snippet = self._line_snippet(node)
        for ps in summary.param_sinks:
            if ps.vuln_type not in self.rules.vulnerabilities or ps.param_index >= len(args):
                continue
            actual = self._evaluate_taint(args[ps.param_index])
            if actual is None or not actual.has_labels:
                continue
            labels = frozenset(l.with_categories(l.vuln_categories & ps.remaining) for l in actual.labels)
            pname = summary.params[ps.param_index] if ps.param_index < len(summary.params) else f"#{ps.param_index}"
            trace = actual.trace + [TraceStep(
                file=self.file_path, line=line,
                description=f"Passed as argument #{ps.param_index} ({pname}) to {summary.qualified_name}()",
                snippet=snippet,
            )] + list(ps.trace)
            fact = TaintFact(labels=labels, filters_applied=dict(actual.filters_applied), trace=trace)
            if not self._relevant(fact, ps.vuln_type):
                continue
            self._record_finding(
                ps.vuln_type, None, ps.sink_function, fact,
                location=(ps.file, ps.line, ps.column, ps.snippet),
                privileged=ps.privileged,
                function_name=summary.qualified_name,
            )

    def _apply_ref_outputs(self, info: CallInfo):
        if info.kind != "function":
            return
        args = info.args
        name = info.short_name
        if name == "settype" and len(args) >= 2:
            key = self._key(args[0])
            fact = self.state.get_taint(key) if key else None
            if fact is not None and re.search(r"(?i)int|float|double|bool", self._text(args[1])):
                self.state.set_taint(key, fact.apply_filter("settype", self.all_categories,
                                                            file=self.file_path, line=args[0].start_point[0] + 1))
            return
        ro = self.rules.get_ref_output(name)
        if ro is None or ro.to_arg >= len(args) or ro.from_arg >= len(args):
            return
        src = self._evaluate_taint(args[ro.from_arg])
        key = self._key(args[ro.to_arg])
        if not key:
            return
        if src is None or not src.has_labels:
            self.state.remove_taint(key)
            return
        fact = src.derive(f"Written by reference into {key} by {name}()",
                          file=self.file_path, line=args[ro.to_arg].start_point[0] + 1)
        if ro.regex_arg is not None and ro.regex_arg < len(args) and self._is_strict_regex(args[ro.regex_arg]):
            fact = fact.apply_filter(f"{name} (strict regex)", self.all_categories)
        self.state.set_taint(key, fact)

    # ==================================================================
    # Evaluation du taint des expressions
    # ==================================================================

    def _evaluate_taint(self, node) -> Optional[TaintFact]:
        if node is None:
            return None
        ntype = node.type

        if ntype == "variable_name":
            key = self._key(node)
            fact = self.state.get_taint(key)
            if fact is not None:
                return fact
            if self.rules.is_source(key):
                return self._source_fact(key, node, self._source_type_for(key))
            return self._class_prop_taint(key)

        if ntype == "subscript_expression":
            return self._eval_subscript(node)

        if ntype in ("member_access_expression", "nullsafe_member_access_expression"):
            return self._eval_member_access(node)

        if ntype == "scoped_property_access_expression":
            key = self._key(node)
            return self.state.get_taint(key) or self._class_prop_taint(key)

        if ntype == "binary_expression":
            return self._eval_binary(node)

        if ntype in ("encapsed_string", "heredoc", "heredoc_body", "shell_command_expression"):
            return self._eval_interpolated(node, "String interpolation")

        if ntype in CALL_NODE_TYPES:
            return self._evaluate_call(node)

        if ntype == "cast_expression":
            return self._eval_cast(node)

        if ntype == "conditional_expression":
            cond = node.child_by_field_name("condition")
            body = node.child_by_field_name("body")
            alt = node.child_by_field_name("alternative")
            t_body = self._evaluate_taint(body) if body is not None else self._evaluate_taint(cond)
            t_alt = self._evaluate_taint(alt)
            return TaintFact.merge(t_body, t_alt, "Ternary expression", self.file_path, node.start_point[0] + 1)

        if ntype == "parenthesized_expression":
            return self._evaluate_taint(node.named_children[0]) if node.named_children else None

        if ntype == "error_suppression_expression" or ntype == "clone_expression" or ntype == "yield_expression":
            return self._evaluate_taint(node.named_children[0]) if node.named_children else None

        if ntype == "assignment_expression":
            self._handle_assignment(node)
            left = node.child_by_field_name("left")
            return self.state.get_taint(self._key(left)) if left is not None else None

        if ntype == "augmented_assignment_expression":
            self._handle_augmented_assignment(node)
            left = node.child_by_field_name("left")
            return self.state.get_taint(self._key(left)) if left is not None else None

        if ntype in ("array_creation_expression", "list_literal"):
            combined = None
            for child in node.named_children:
                combined = TaintFact.merge(combined, self._evaluate_taint(child))
            return combined

        if ntype == "array_element_initializer":
            return self._evaluate_taint(node.named_children[-1]) if node.named_children else None

        if ntype in ("argument", "variadic_unpacking", "spread_element", "by_ref"):
            return self._evaluate_taint(node.named_children[-1]) if node.named_children else None

        if ntype == "match_expression":
            combined = None
            body = node.child_by_field_name("body")
            if body is not None:
                for arm in body.named_children:
                    ret = arm.child_by_field_name("return_expression")
                    combined = TaintFact.merge(combined, self._evaluate_taint(ret))
            return combined

        if ntype == "unary_op_expression":
            return None  # !, -, +, ~ : resultat bool/numerique

        if ntype in CLOSURE_NODE_TYPES:
            return None

        if ntype == "dynamic_variable_name":
            return None

        return None

    def _eval_subscript(self, node) -> Optional[TaintFact]:
        key = self._key(node)
        exact = self.state.get_taint(key)
        if exact is not None:
            return exact

        children = node.named_children
        if not children:
            return None
        base = children[0]
        index = children[1] if len(children) > 1 else None
        root = self._root_variable(node)

        if root is not None and self.rules.is_source(root):
            # $GLOBALS['x']
            if root == "$GLOBALS":
                lit = self._literal_text(index) if index is not None else None
                if lit is not None:
                    self._uses_globals = True
                    g = self.global_state.get_taint("$" + lit)
                    return g.derive(f"Read from $GLOBALS['{lit}']", file=self.file_path,
                                    line=node.start_point[0] + 1) if g is not None else None
                return None
            # $_SERVER : seules certaines cles sont controlees par le client
            if root == "$_SERVER" and base.type == "variable_name":
                lit = self._literal_text(index) if index is not None else None
                if lit is not None and not (lit.startswith("HTTP_") or lit in self.rules.dangerous_server_keys):
                    return None
            # $_FILES[...]['tmp_name'|'size'|'error'] : controle serveur
            if root == "$_FILES":
                lit = self._literal_text(index) if index is not None else None
                if lit in ("tmp_name", "size", "error"):
                    return None
            return self._source_fact(key, node, self._source_type_for(root))

        base_taint = self._evaluate_taint(base)
        if base_taint is not None and base_taint.has_labels:
            return base_taint.derive(f"Array access {key}", file=self.file_path, line=node.start_point[0] + 1)
        return None

    def _eval_member_access(self, node) -> Optional[TaintFact]:
        key = self._key(node)
        exact = self.state.get_taint(key)
        if exact is not None:
            return exact
        obj = node.child_by_field_name("object")
        if obj is None:
            return None
        if self.rules.request_properties and self._is_request_object(obj):
            return self._source_fact(key, node, "user_input")
        prop = self._class_prop_taint(key)
        if prop is not None:
            return prop
        obj_taint = self._evaluate_taint(obj)
        if obj_taint is not None and obj_taint.has_labels:
            return obj_taint.derive(f"Property access {key}", file=self.file_path, line=node.start_point[0] + 1)
        return None

    def _class_prop_taint(self, key: str) -> Optional[TaintFact]:
        if self.current_class is None:
            return None
        cs = self.class_states.get(self.current_class)
        if cs is None:
            return None
        return cs.get_taint(key)

    def _eval_binary(self, node) -> Optional[TaintFact]:
        op_node = node.child_by_field_name("operator")
        op = self._text(op_node) if op_node is not None else "."
        if op in ARITHMETIC_OPS:
            return None
        # Concatenation (.) / coalescence (??) : aplatir la chaine pour eviter la recursion profonde
        operands: list = []
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "binary_expression":
                o = n.child_by_field_name("operator")
                if o is not None and self._text(o) == op:
                    stack.append(n.child_by_field_name("right"))
                    stack.append(n.child_by_field_name("left"))
                    continue
            operands.append(n)
        combined = None
        for operand in operands:
            combined = TaintFact.merge(combined, self._evaluate_taint(operand))
        return combined

    def _eval_interpolated(self, node, description: str) -> Optional[TaintFact]:
        combined = None
        for child in node.named_children:
            if child.type in ("string_content", "heredoc_start", "heredoc_end", "escape_sequence"):
                continue
            if child.type == "heredoc_body":
                combined = TaintFact.merge(combined, self._eval_interpolated(child, description))
                continue
            combined = TaintFact.merge(combined, self._evaluate_taint(child))
        return combined

    def _eval_cast(self, node) -> Optional[TaintFact]:
        type_node = node.child_by_field_name("type")
        value_node = node.child_by_field_name("value")
        if value_node is None:
            return None
        value_taint = self._evaluate_taint(value_node)
        if value_taint is None:
            return None
        if type_node is not None:
            cast_type = self._text(type_node).strip("()").lower()
            fi = self.rules.get_filter_info(f"_cast_{cast_type}")
            if fi is not None:
                return value_taint.apply_filter(f"({cast_type}) cast", fi.neutralizes,
                                                file=self.file_path, line=node.start_point[0] + 1)
        return value_taint

    # --- Appels (valeur) ---

    def _evaluate_call(self, node) -> Optional[TaintFact]:
        info = self._call_info(node)
        if info is None:
            return None
        args = info.args
        name = info.short_name
        line = node.start_point[0] + 1

        if info.kind == "new":
            return None  # objet opaque ; les sinks du constructeur sont traites par _handle_call

        if info.kind == "dynamic":
            return self._unknown_result(info, "unknown dynamic call")

        # 1. Sources
        if info.kind == "function" and self.rules.is_source_function(name):
            cond = self.rules.source_function_condition(name)
            if cond is None or (cond[0] < len(args) and cond[1].search(self._text(args[cond[0]]))):
                stype = "environment" if name in ("getenv",) else "function"
                fact = self._source_fact(f"{name}()", node, stype)
                fi = self.rules.get_filter_info(name)
                if fi is not None and fi.flags_arg is not None:
                    cats = self._flag_categories(args, fi.flags_arg)
                    if cats:
                        fact = fact.apply_filter(f"{name}[{self._flags_text(args, fi.flags_arg)}]", cats,
                                                 file=self.file_path, line=line)
                return fact
        if info.kind in ("method", "static"):
            if name in self.rules.source_methods or (
                self._is_request_object(info.obj_node) and name in self.rules.request_methods
            ):
                return self._source_fact(f"{info.display_name}()", node, "user_input")

        # 2. Filtres / sanitizers
        fi = self._filter_for(info)
        if fi is not None:
            return self._apply_filter_call(fi, info, node)
        if info.kind == "function" and name in ("preg_replace", "mb_ereg_replace") and len(args) >= 3:
            cats = self._whitelist_regex_categories(args[0], args[1])
            if cats:
                t = self._evaluate_taint(args[2])
                if t is None or not t.has_labels:
                    return None
                return t.apply_filter(f"{name} (character whitelist)", cats, file=self.file_path, line=line)
        if info.kind == "function" and name == "array_map" and len(args) >= 2:
            cb = self._literal_text(args[0])
            cb_filter = self.rules.get_filter_info(_last_segment(cb)) if cb else None
            if cb_filter is not None:
                t = self._evaluate_taint(args[1])
                if t is None:
                    return None
                return t.apply_filter(f"array_map('{cb}')", cb_filter.neutralizes, file=self.file_path, line=line)

        # 3. Effets par reference (preg_match -> $matches) puis valeurs booleennes/sures
        self._apply_ref_outputs(info)
        if info.kind == "function" and (self.rules.get_validator(name) is not None or self.rules.is_safe_function(name)):
            return None

        # 4. Propagateurs
        if (info.kind == "function" and self.rules.is_propagator(name)) or \
           (info.kind in ("method", "static") and name in self.rules.method_propagators):
            combined = None
            for a in args:
                combined = TaintFact.merge(combined, self._evaluate_taint(a))
            if info.kind == "method" and info.obj_node is not None:
                combined = TaintFact.merge(combined, self._evaluate_taint(info.obj_node))
            if combined is not None and combined.has_labels:
                return combined.derive(f"Propagated through {info.display_name}()", file=self.file_path, line=line)
            return None

        # 5. Resume de fonction user-defined
        summary = self._resolve_callee(info)
        if summary is not None:
            return self._substitute_return(summary, info, node)

        # 6. Heuristique : nom evoquant un nettoyage
        pat = self.rules.assume_sanitizer_pattern
        if pat is not None and name and pat.search(name):
            combined = None
            for a in args:
                combined = TaintFact.merge(combined, self._evaluate_taint(a))
            if combined is not None and combined.has_labels:
                return combined.apply_filter(f"{name} (assumed sanitizer by name)", self.all_categories,
                                             file=self.file_path, line=line)
            return None

        # 7. Sink connu : resultat opaque (resultat SQL, handle...) sauf si aussi propagateur (traite plus haut)
        if self._sinks_for(info):
            return None

        # 8. Inconnu : conservatif
        return self._unknown_result(info, None)

    def _unknown_result(self, info: CallInfo, label: Optional[str]) -> Optional[TaintFact]:
        combined = None
        for a in info.args:
            combined = TaintFact.merge(combined, self._evaluate_taint(a))
        if info.kind in ("method", "dynamic") and info.obj_node is not None:
            combined = TaintFact.merge(combined, self._evaluate_taint(info.obj_node))
        if combined is None or not combined.has_labels:
            return None
        if label is None:
            label = "unknown method" if info.kind in ("method", "static") else "unknown function"
        return combined.derive(f"Through {label} {info.display_name}()", file=self.file_path,
                               line=info.node.start_point[0] + 1)

    def _filter_for(self, info: CallInfo) -> Optional[FilterInfo]:
        name = info.short_name
        if not name:
            return None
        if info.kind == "function":
            return self.rules.get_filter_info(name)
        if info.kind == "method":
            for cls in self._class_hints(info.obj_node, name):
                fi = self.rules.get_filter_info(f"{cls}::{name}")
                if fi is not None:
                    return fi
            return self.rules.get_filter_info("->" + name)
        if info.kind == "static":
            if info.class_name:
                fi = self.rules.get_filter_info(f"{info.class_name}::{name}")
                if fi is not None:
                    return fi
            return self.rules.get_filter_info("->" + name)
        return None

    def _apply_filter_call(self, fi: FilterInfo, info: CallInfo, node) -> Optional[TaintFact]:
        args = info.args
        line = node.start_point[0] + 1
        name = info.display_name
        if fi.flags_arg is not None:
            if fi.arg >= len(args):
                return None
            t = self._evaluate_taint(args[fi.arg])
            if t is None or not t.has_labels:
                return None
            cats = self._flag_categories(args, fi.flags_arg)
            if not cats:
                return t.derive(f"Through {name}() without a sanitizing FILTER_* flag", file=self.file_path, line=line)
            return t.apply_filter(f"{name}[{self._flags_text(args, fi.flags_arg)}]", cats, file=self.file_path, line=line)

        idx = fi.arg if fi.arg >= 0 else len(args) + fi.arg
        if idx < 0 or idx >= len(args):
            return None
        if fi.variadic:
            t = None
            for a in args[idx:]:
                t = TaintFact.merge(t, self._evaluate_taint(a))
        else:
            t = self._evaluate_taint(args[idx])
        if t is None or not t.has_labels:
            return None
        if fi.confidence <= Confidence.LOW:
            # Sanitizer faible (addslashes...) : le taint reste, la confiance du finding baisse
            return t.derive(f"Weakly sanitized by {name}() (bypassable)", file=self.file_path, line=line)
        return t.apply_filter(name, fi.neutralizes, file=self.file_path, line=line)

    def _flag_categories(self, args: list, flags_arg: int) -> list[str]:
        if flags_arg >= len(args):
            return []
        text = self._text(args[flags_arg])
        cats: list[str] = []
        for flag, c in self.rules.filter_flags.items():
            if re.search(r"\b" + re.escape(flag) + r"\b", text):
                cats.extend(c)
        return cats

    def _flags_text(self, args: list, flags_arg: int) -> str:
        if flags_arg >= len(args):
            return ""
        m = re.findall(r"FILTER_[A-Z_]+", self._text(args[flags_arg]))
        return "|".join(m) if m else self._text(args[flags_arg])[:30]

    def _substitute_return(self, summary: FunctionSummary, info: CallInfo, node) -> Optional[TaintFact]:
        rf = summary.return_fact
        if rf is None or not rf.has_labels:
            return None
        args = info.args
        new_labels: set = set()
        prefix: list[TraceStep] = []
        filters: dict = dict(rf.filters_applied)
        for l in rf.labels:
            if l.is_param:
                if l.param_index >= len(args):
                    continue
                actual = self._evaluate_taint(args[l.param_index])
                if actual is None:
                    continue
                for al in actual.labels:
                    new_labels.add(al.with_categories(al.vuln_categories & l.vuln_categories))
                if len(actual.trace) > len(prefix):
                    prefix = list(actual.trace)
                filters.update(actual.filters_applied)
            else:
                new_labels.add(l)
        if not new_labels:
            return None
        trace = prefix + list(rf.trace) + [TraceStep(
            file=self.file_path, line=node.start_point[0] + 1,
            description=f"Returned from {summary.qualified_name}() into caller",
            snippet=self._line_snippet(node),
        )]
        return TaintFact(labels=frozenset(new_labels), filters_applied=filters, trace=trace)

    # ==================================================================
    # Gardes (conditions)
    # ==================================================================

    def _condition_guards(self, node) -> tuple[dict, dict]:
        """Retourne (then_guards, else_guards) : key -> (categories, nom, confiance)."""
        empty: tuple[dict, dict] = ({}, {})
        if node is None:
            return empty
        t = node.type
        if t == "parenthesized_expression":
            return self._condition_guards(node.named_children[0]) if node.named_children else empty
        if t == "unary_op_expression":
            op = node.child_by_field_name("operator")
            if op is not None and self._text(op) == "!":
                th, el = self._condition_guards(node.child_by_field_name("argument"))
                return el, th
            return empty
        if t == "binary_expression":
            op_node = node.child_by_field_name("operator")
            op = self._text(op_node) if op_node is not None else ""
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if op in ("&&", "and"):
                a = self._condition_guards(left)
                b = self._condition_guards(right)
                return {**a[0], **b[0]}, {}
            if op in ("||", "or"):
                a = self._condition_guards(left)
                b = self._condition_guards(right)
                return {}, {**a[1], **b[1]}
            if op in ("===", "==", "!==", "!="):
                lit, expr = (left, right) if self._is_literal(left) else ((right, left) if self._is_literal(right) else (None, None))
                if lit is None:
                    return empty
                lit_text = self._text(lit).strip()
                eq = op in ("===", "==")
                if lit_text in FALSY_LITERALS or lit_text in TRUTHY_LITERALS:
                    g = self._condition_guards(expr)
                    truthy = lit_text in TRUTHY_LITERALS
                    if (eq and truthy) or (not eq and not truthy):
                        return g
                    return g[1], g[0]
                key = self._guard_target(expr)
                if key is None:
                    return empty
                guard = {key: (self.all_categories, "equals literal", Confidence.HIGH)}
                return (guard, {}) if eq else ({}, guard)
            return empty
        if t in CALL_NODE_TYPES:
            info = self._call_info(node)
            if info is None or info.kind != "function":
                return empty
            name = info.short_name
            args = info.args
            v = self.rules.get_validator(name)
            if v is not None:
                if v.arg >= len(args):
                    return empty
                if v.regex_arg is not None:
                    if v.regex_arg >= len(args) or not self._is_strict_regex(args[v.regex_arg]):
                        return empty
                key = self._guard_target(args[v.arg])
                if key is None:
                    return empty
                return {key: (frozenset(v.neutralizes), name, v.confidence)}, {}
            if name in ("filter_var", "filter_input"):
                fi = self.rules.get_filter_info(name)
                if fi is None or fi.flags_arg is None:
                    return empty
                cats = self._flag_categories(args, fi.flags_arg)
                key = self._guard_target(args[fi.arg]) if fi.arg < len(args) else None
                if cats and key:
                    return {key: (frozenset(cats), f"{name}[{self._flags_text(args, fi.flags_arg)}]", Confidence.HIGH)}, {}
                return empty
            if name in ("isset", "empty", "array_key_exists_dummy"):
                # isset($allowed[$x]) / !empty($map[$x]) : $x est une cle d'une whitelist
                guards: dict = {}
                for a in args:
                    target = a.named_children[-1] if a.type == "argument" and a.named_children else a
                    if target.type == "subscript_expression" and len(target.named_children) >= 2:
                        base, index = target.named_children[0], target.named_children[1]
                        base_key = self._key(base)
                        base_taint = self.state.get_taint(base_key) if base_key else None
                        if (base_taint is None or not base_taint.has_labels) and not self.rules.is_source(base_key or ""):
                            key = self._guard_target(index)
                            if key:
                                guards[key] = (self.all_categories, f"{name} whitelist lookup", Confidence.HIGH)
                if name == "empty":
                    return {}, guards
                return guards, {}
            return empty
        return empty

    def _privilege_guards(self, node) -> tuple[bool, bool]:
        """(then_privileged, else_privileged) pour current_user_can() & co."""
        if node is None:
            return False, False
        t = node.type
        if t == "parenthesized_expression":
            return self._privilege_guards(node.named_children[0]) if node.named_children else (False, False)
        if t == "unary_op_expression":
            op = node.child_by_field_name("operator")
            if op is not None and self._text(op) == "!":
                a, b = self._privilege_guards(node.child_by_field_name("argument"))
                return b, a
            return False, False
        if t == "binary_expression":
            op_node = node.child_by_field_name("operator")
            op = self._text(op_node) if op_node is not None else ""
            a = self._privilege_guards(node.child_by_field_name("left"))
            b = self._privilege_guards(node.child_by_field_name("right"))
            if op in ("&&", "and"):
                return a[0] or b[0], False
            if op in ("||", "or"):
                return False, a[1] or b[1]
            if op in ("===", "==", "!==", "!="):
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                lit = left if self._is_literal(left) else (right if self._is_literal(right) else None)
                expr = right if lit is left else left
                if lit is None:
                    return False, False
                g = self._privilege_guards(expr)
                lt = self._text(lit).strip()
                eq = op in ("===", "==")
                truthy = lt in TRUTHY_LITERALS
                if (eq and truthy) or (not eq and lt in FALSY_LITERALS):
                    return g
                return g[1], g[0]
            return False, False
        if t in CALL_NODE_TYPES:
            info = self._call_info(node)
            if info is not None and info.short_name in self.rules.privilege_guards:
                return True, False
        return False, False

    def _guard_target(self, node) -> Optional[str]:
        """Cle de variable visee par une garde : $x, $_GET['x'], trim($x), (string)$x ..."""
        if node is None:
            return None
        t = node.type
        if t == "argument":
            return self._guard_target(node.named_children[-1]) if node.named_children else None
        if t in ("variable_name", "subscript_expression", "member_access_expression",
                 "nullsafe_member_access_expression", "scoped_property_access_expression"):
            return self._key(node)
        if t == "parenthesized_expression" or t == "cast_expression":
            inner = node.child_by_field_name("value") if t == "cast_expression" else (node.named_children[0] if node.named_children else None)
            return self._guard_target(inner)
        if t in CALL_NODE_TYPES:
            info = self._call_info(node)
            if info is not None and info.kind == "function" and info.args and self.rules.is_propagator(info.short_name):
                return self._guard_target(info.args[0])
        return None

    def _apply_guards(self, guards: dict):
        for key, (cats, name, conf) in guards.items():
            self._apply_guard(key, cats, name, conf)

    def _apply_guard(self, key: str, cats, name: str, conf: Confidence):
        fact = self.state.get_taint(key)
        if fact is None:
            if self.rules.is_source(key):
                fact = self._source_fact(key, None, self._source_type_for(key))
            else:
                fact = self._class_prop_taint(key)
        if fact is None or not fact.has_labels:
            return
        if conf <= Confidence.LOW:
            return
        new = fact.apply_filter(name, cats)
        new.trace[-1].description = f"Validated by {name} (branch guard)"
        self.state.set_taint(key, new)

    def _terminates(self, body) -> bool:
        """Vrai si le bloc se termine toujours par return/exit/throw/break/continue."""
        if body is None:
            return False
        if body.type in ("compound_statement", "colon_block"):
            stmts = [c for c in body.named_children if c.type != "comment"]
            if not stmts:
                return False
            return self._terminates(stmts[-1])
        t = body.type
        if t in ("return_statement", "exit_statement", "break_statement", "continue_statement", "goto_statement"):
            return True
        if t == "expression_statement":
            expr = body.named_children[0] if body.named_children else None
            if expr is None:
                return False
            if expr.type == "throw_expression":
                return True
            if expr.type in CALL_NODE_TYPES:
                info = self._call_info(expr)
                if info is not None and info.kind == "function" and info.short_name in self.rules.terminators:
                    return True
            return False
        if t == "throw_statement":
            return True
        if t == "if_statement":
            alts = [c for c in body.children if c.type in ("else_if_clause", "else_clause")]
            if not alts:
                return False
            if not self._terminates(body.child_by_field_name("body")):
                return False
            for alt in alts:
                if not self._terminates(alt.child_by_field_name("body")):
                    return False
            return alts[-1].type == "else_clause"
        return False

    # ==================================================================
    # Recording des findings
    # ==================================================================

    def _relevant(self, taint: TaintFact, vuln_type: str) -> bool:
        return any(vuln_type in l.vuln_categories for l in taint.labels)

    def _record_finding(
        self,
        vuln_type: str,
        node,
        sink_function: str,
        taint: TaintFact,
        sink_conf: Confidence = Confidence.HIGH,
        location: Optional[tuple] = None,
        privileged: bool = False,
        function_name: Optional[str] = None,
    ):
        rule = self.rules.vulnerabilities.get(vuln_type)
        if rule is None:
            return
        if location is not None:
            file_path, line, column, snippet = location
        else:
            file_path = self.file_path
            line = node.start_point[0] + 1
            column = node.start_point[1]
            snippet = self._line_snippet(node)

        privileged = privileged or self.privilege_depth > 0
        real = [l for l in taint.labels if not l.is_param and vuln_type in l.vuln_categories]
        params = [l for l in taint.labels if l.is_param and vuln_type in l.vuln_categories]

        sink_step = TraceStep(file=file_path, line=line, column=column,
                              description=f"Reaches {sink_function}() sink [{vuln_type}]", snippet=snippet)
        trace = list(taint.trace)
        if not trace or trace[-1].description != sink_step.description or trace[-1].line != line:
            trace.append(sink_step)

        # Sinks atteints par des parametres -> resume de la fonction courante
        if params and self.current_function is not None:
            penalty = self._propagation_penalty(trace)
            for l in params:
                ps = ParamSink(
                    param_index=l.param_index, vuln_type=vuln_type, sink_function=sink_function,
                    file=file_path, line=line, column=column, snippet=snippet,
                    remaining=l.vuln_categories, trace=trace, privileged=privileged,
                    confidence_penalty=penalty,
                )
                if not any(p.param_index == ps.param_index and p.vuln_type == ps.vuln_type and p.line == ps.line and p.file == ps.file
                           for p in self.current_function.param_sinks):
                    self.current_function.param_sinks.append(ps)

        if not real:
            return

        source = sorted(real, key=lambda l: (l.source_line, l.source_var))[0]
        key = (file_path, line, vuln_type, sink_function, source.source_var)
        if key in self._seen:
            return
        self._seen.add(key)

        confidence = self._confidence(trace, real, sink_conf)
        severity = rule.severity
        tags: list[str] = []
        if privileged:
            tags.append("privileged-context")
            severity = Severity(max(Severity.INFO, severity - 1))
        if function_name is None and self.current_function is not None:
            function_name = self.current_function.qualified_name
        sanitizers = sorted(taint.filters_applied.keys())

        title = f"{vuln_type.replace('_', ' ').title()} in {sink_function}()"
        if privileged:
            title += " (admin-only context)"

        self.findings.append(Finding(
            vuln_type=vuln_type,
            severity=severity,
            confidence=confidence,
            cwe=rule.cwe,
            owasp=rule.owasp,
            title=title,
            description=rule.description,
            file_path=file_path,
            line=line,
            column=column,
            sink_function=sink_function,
            source_variable=source.source_var,
            code_snippet=snippet,
            data_flow=trace,
            remediation=rule.remediation,
            detection_mode="taint",
            function_name=function_name or "",
            tags=tags,
            sanitizers_applied=sanitizers,
        ))

    def _propagation_penalty(self, trace: list[TraceStep]) -> int:
        penalty = 0
        for step in trace:
            d = step.description
            if "unknown method" in d or "unknown dynamic" in d or "Weakly sanitized" in d:
                penalty = max(penalty, 2)
            elif "unknown function" in d:
                penalty = max(penalty, 1)
        return penalty

    def _confidence(self, trace: list[TraceStep], labels: list, sink_conf: Confidence) -> Confidence:
        conf = int(sink_conf)
        conf -= self._propagation_penalty(trace)
        if any(l.source_type in LOW_CONF_SOURCE_TYPES for l in labels) and not any(l.source_type == "user_input" for l in labels):
            conf = min(conf, Confidence.LOW)
        return Confidence(max(Confidence.LOW, min(Confidence.HIGH, conf)))

    # ==================================================================
    # Helpers
    # ==================================================================

    def _text(self, node) -> str:
        if node is None:
            return ""
        return self.source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _key(self, node) -> str:
        """Cle normalisee d'une variable/propriete/element ($x, $this->p, $_GET['k'])."""
        if node is None:
            return ""
        if node.type == "argument" and node.named_children:
            return self._key(node.named_children[-1])
        text = self._text(node)
        text = _WS_RE.sub("", text).replace('"', "'").replace("?->", "->")
        return text

    def _line_snippet(self, node) -> str:
        if node is None:
            return ""
        idx = node.start_point[0]
        if 0 <= idx < len(self.lines):
            return self.lines[idx].strip()
        return ""

    def _is_literal(self, node) -> bool:
        return node is not None and node.type in ("string", "encapsed_string", "integer", "float", "boolean", "null",
                                                   "name", "class_constant_access_expression") \
            and (node.type != "encapsed_string" or all(c.type in ("string_content", "escape_sequence") for c in node.named_children))

    def _literal_text(self, node) -> Optional[str]:
        """Contenu d'un litteral string/int (sans quotes), None sinon."""
        if node is None:
            return None
        if node.type == "argument" and node.named_children:
            return self._literal_text(node.named_children[-1])
        if node.type == "string":
            return self._text(node)[1:-1]
        if node.type == "encapsed_string":
            if all(c.type in ("string_content", "escape_sequence") for c in node.named_children):
                return self._text(node)[1:-1]
            return None
        if node.type in ("integer", "float"):
            return self._text(node)
        return None

    def _leading_literal(self, node) -> Optional[str]:
        """Texte du premier litteral d'une expression ("Location: " . $x -> "Location: ")."""
        n = node
        if n is not None and n.type == "argument" and n.named_children:
            n = n.named_children[-1]
        while n is not None:
            if n.type == "binary_expression":
                n = n.child_by_field_name("left")
                continue
            if n.type == "parenthesized_expression" and n.named_children:
                n = n.named_children[0]
                continue
            break
        if n is None:
            return None
        if n.type == "string":
            return self._text(n)[1:-1]
        if n.type == "encapsed_string":
            first = n.named_children[0] if n.named_children else None
            if first is not None and first.type == "string_content":
                return self._text(first)
            return None
        if n.type == "heredoc":
            body = n.child_by_field_name("value")
            first = body.named_children[0] if body is not None and body.named_children else None
            if first is not None and first.type == "string_content":
                return self._text(first)
        return None

    def _root_variable(self, node) -> Optional[str]:
        n = node
        while n is not None and n.type in ("subscript_expression", "member_access_expression", "nullsafe_member_access_expression"):
            n = n.named_children[0] if n.named_children else None
        if n is not None and n.type == "variable_name":
            return self._text(n)
        return None

    def _source_type_for(self, var: str) -> str:
        root = var.split("[", 1)[0]
        if root in ("$_ENV", "$argv"):
            return "environment"
        return "user_input"

    def _source_fact(self, var_text: str, node, source_type: str) -> TaintFact:
        line = node.start_point[0] + 1 if node is not None else 0
        return TaintFact(
            labels=frozenset({TaintLabel(
                source_type=source_type,
                source_var=var_text,
                source_file=self.file_path,
                source_line=line,
                vuln_categories=self.all_categories,
            )}),
            trace=[TraceStep(
                file=self.file_path, line=line,
                description=f"Source: {var_text}",
                snippet=self._line_snippet(node) if node is not None else "",
            )],
        )

    def _is_request_object(self, obj_node) -> bool:
        if obj_node is None:
            return False
        text = _WS_RE.sub("", self._text(obj_node))
        pat = self.rules.request_object_pattern
        if pat is not None and pat.match(text):
            return True
        if obj_node.type in ("variable_name", "member_access_expression"):
            t = self.state.get_type(self._key(obj_node))
            if t and t in self.rules.request_types:
                return True
        if obj_node.type in ("name", "qualified_name"):
            return _last_segment(text) in ("Request", "Input") and pat is not None
        return False

    def _short_obj_text(self, obj_node) -> str:
        if obj_node is None:
            return ""
        text = _WS_RE.sub("", self._text(obj_node))
        return text if len(text) <= 40 else text[:37] + "..."

    def _class_of_expr(self, node) -> Optional[str]:
        if node is None:
            return None
        if node.type == "object_creation_expression":
            for c in node.named_children:
                if c.type in ("name", "qualified_name"):
                    return _last_segment(self._text(c))
            return None
        if node.type in ("variable_name", "member_access_expression", "scoped_property_access_expression"):
            key = self._key(node)
            t = self.state.get_type(key)
            if t:
                return t
            if key == "$this":
                return self.current_class
            return None
        if node.type == "clone_expression" and node.named_children:
            return self._class_of_expr(node.named_children[0])
        if node.type == "parenthesized_expression" and node.named_children:
            return self._class_of_expr(node.named_children[0])
        return None

    def _class_hints(self, obj_node, method: str) -> list[str]:
        """Classes plausibles de l'objet : type connu, puis heuristique sur le nom de variable."""
        hints: list[str] = []
        if obj_node is None:
            return hints
        known = self._class_of_expr(obj_node)
        if known:
            hints.append(known)
        text = _WS_RE.sub("", self._text(obj_node)).lower()
        m = re.search(r"([a-z_][a-z0-9_]*)['\]\)]*$", text)
        var_name = m.group(1) if m else ""
        if var_name in ("this", ""):
            return hints
        for cls in self.rules.class_names_for_method(method):
            if cls == var_name or (len(var_name) >= 3 and var_name in cls) or (len(cls) >= 3 and cls in var_name):
                if cls not in [h.lower() for h in hints]:
                    hints.append(cls)
        return hints

    _WHITELIST_CLASS_RE = re.compile(r"^\[\^([^\]]*)\]([+*])?$")
    _SAFE_CLASS_CONTENT_RE = re.compile(r"^(?:[a-zA-Z0-9_\- ]|\\[wdsA-Za-z]|\.|a-z|A-Z|0-9|\\-)*$")

    def _whitelist_regex_categories(self, pattern_node, replacement_node) -> Optional[frozenset]:
        """preg_replace('/[^a-z0-9_]/', '', $x) ne laisse passer que des caracteres surs.

        Retourne les categories neutralisees (toutes, sauf path_traversal/file_inclusion
        si '.' ou '/' restent autorises), ou None si le pattern n'est pas un whitelist.
        """
        repl = self._literal_text(replacement_node)
        if repl is None or re.search(r"[<>'\"`;|&$\\/]", repl):
            return None
        lit = self._literal_text(pattern_node)
        if not lit or len(lit) < 4:
            return None
        delim = lit[0]
        closing = {"(": ")", "[": "]", "{": "}", "<": ">"}.get(delim, delim)
        end = lit.rfind(closing)
        if end <= 0:
            return None
        body = lit[1:end]
        kept = None
        if body in ("\\W", "\\W+", "\\W*", "[\\W]", "[\\W]+", "\\D", "\\D+", "\\D*"):
            kept = ""
        else:
            m = self._WHITELIST_CLASS_RE.match(body)
            if m is None:
                return None
            kept = m.group(1)
            if not self._SAFE_CLASS_CONTENT_RE.match(kept):
                return None
        cats = set(self.all_categories)
        if "." in kept or "/" in kept or "\\s" in kept or " " in kept:
            cats -= {"path_traversal", "file_inclusion", "ssrf", "open_redirect"}
        return frozenset(cats)

    _STRICT_REGEX_FORBIDDEN = re.compile(r"(?<!\\)\.|\[\^|\\[SDWX]|\\p\{")

    def _is_strict_regex(self, node) -> bool:
        """Regex litterale ancree (^...$) sans joker : garantit un jeu de caracteres restreint."""
        lit = self._literal_text(node)
        if not lit or len(lit) < 3:
            return False
        delim = lit[0]
        closing = {"(": ")", "[": "]", "{": "}", "<": ">"}.get(delim, delim)
        end = lit.rfind(closing)
        if end <= 0:
            return False
        body = lit[1:end]
        anchored_start = body.startswith("^") or body.startswith("\\A")
        anchored_end = body.endswith("$") or body.endswith("\\z") or body.endswith("\\Z")
        if not (anchored_start and anchored_end):
            return False
        if self._STRICT_REGEX_FORBIDDEN.search(body):
            return False
        if "|" in body:
            inner = body.lstrip("^").rstrip("$")
            if not (inner.startswith("(") and inner.endswith(")")):
                return False
        return True

    # ==================================================================
    # Dispatch table
    # ==================================================================

    _handlers = {
        "program": _walk_children,
        "compound_statement": _walk_children,
        "colon_block": _walk_children,
        "namespace_definition": _walk_children,
        "declaration_list": _walk_children,
        "expression_statement": _handle_expression_statement,
        "echo_statement": _handle_echo,
        "print_intrinsic": _handle_print,
        "exit_statement": _handle_exit,
        "include_expression": _handle_include,
        "require_expression": _handle_include,
        "include_once_expression": _handle_include,
        "require_once_expression": _handle_include,
        "shell_command_expression": _handle_shell_command,
        "if_statement": _handle_if,
        "while_statement": _handle_while,
        "do_statement": _handle_do,
        "for_statement": _handle_for,
        "foreach_statement": _handle_foreach,
        "switch_statement": _handle_switch,
        "try_statement": _handle_try,
        "return_statement": _handle_return,
        "global_declaration": _handle_global,
        "unset_statement": _handle_unset,
        "function_definition": _handle_noop,
        "method_declaration": _handle_noop,
        "class_declaration": _handle_noop,
        "trait_declaration": _handle_noop,
        "enum_declaration": _handle_noop,
        "interface_declaration": _handle_noop,
        "function_static_declaration": _handle_noop,
        "const_declaration": _handle_noop,
        "namespace_use_declaration": _handle_noop,
        "text": _handle_noop,
        "comment": _handle_noop,
    }


def findings_from_uncalled_summaries(ctx: CrossFileContext, rules: "RulesConfig") -> list[Finding]:
    """Mode --taint-params : les parametres des fonctions jamais appelees dans le
    projet (points d'entree : hooks, controleurs, API) sont consideres comme
    potentiellement controles par l'utilisateur (confiance basse)."""
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for summary in ctx.all_summaries():
        if summary.name.lower() in ctx.called_names:
            continue
        if summary.name.lower() in ("__construct", "__destruct", "__get", "__set", "__toString"):
            continue
        for ps in summary.param_sinks:
            rule = rules.vulnerabilities.get(ps.vuln_type)
            if rule is None:
                continue
            pname = summary.params[ps.param_index] if ps.param_index < len(summary.params) else f"#{ps.param_index}"
            key = (ps.file, ps.line, ps.vuln_type, ps.sink_function, pname)
            if key in seen:
                continue
            seen.add(key)
            severity = rule.severity
            tags = ["uncalled-entry-point"]
            if ps.privileged:
                tags.append("privileged-context")
                severity = Severity(max(Severity.INFO, severity - 1))
            findings.append(Finding(
                vuln_type=ps.vuln_type,
                severity=severity,
                confidence=Confidence.LOW,
                cwe=rule.cwe,
                owasp=rule.owasp,
                title=f"{ps.vuln_type.replace('_', ' ').title()} in {ps.sink_function}() via parameter {pname} of {summary.qualified_name}()",
                description=rule.description + " (parameter of a function never called from analyzed code: assumed user-controlled)",
                file_path=ps.file,
                line=ps.line,
                column=ps.column,
                sink_function=ps.sink_function,
                source_variable=f"{pname} (parameter of {summary.qualified_name})",
                code_snippet=ps.snippet,
                data_flow=list(ps.trace),
                remediation=rule.remediation,
                detection_mode="taint",
                function_name=summary.qualified_name,
                tags=tags,
            ))
    return findings
