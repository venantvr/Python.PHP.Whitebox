# analysis/taint_tracker.py - Moteur complet de taint analysis intra-procedural

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from analysis.taint_state import TaintLabel, TaintFact, TraceStep, TaintState
from report.finding import Finding
from config.schema import Severity, Confidence
from utils.ast_helpers import (
    get_node_text,
    get_argument_nodes,
    get_function_name,
    find_child_by_type,
    get_code_snippet,
)

if TYPE_CHECKING:
    from config.loader import RulesConfig
    from analysis.cross_file_context import CrossFileContext

# Categories de vulns par defaut pour les sources user_input
ALL_VULN_CATEGORIES = frozenset({
    "sql_injection", "xss", "rce", "code_injection", "file_inclusion",
    "path_traversal", "insecure_upload", "insecure_deserialization",
    "ssrf", "xxe", "open_redirect", "ldap_injection", "session_fixation",
})


class TaintTracker:
    """Moteur de taint analysis forward intra-procedural sur l'AST tree-sitter PHP.

    Parcourt l'AST via une dispatch table (_handlers) qui mappe chaque type de
    noeud a un handler specifique. L'evaluation du taint est recursive :
    _evaluate_taint(node) descend dans les sous-expressions pour determiner si
    une valeur est contaminee.

    Strategie:
      - Les sources ($_GET, $_POST, etc.) introduisent un TaintFact avec toutes
        les categories de vulns possibles (ALL_VULN_CATEGORIES).
      - Les filtres/sanitizers retirent des categories specifiques (ex:
        htmlspecialchars neutralise xss, mais pas sql_injection).
      - Les propagateurs (trim, strtolower, etc.) transmettent le taint intact.
      - Aux points de jonction (if/else, ternaire), on fait un merge conservatif
        (union) : si tainted dans au moins une branche, tainted apres le join.
      - Chaque propagation enregistre un TraceStep pour reconstituer le flux
        source -> intermediaires -> sink dans les findings.

    Interactions inter-fichiers:
      - Herite du taint exporte par les fichiers inclus via CrossFileContext.
      - Les fonctions inconnues sont traitees de maniere conservative : si un
        argument est tainted, le retour est considere tainted.
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
        self.tree = tree
        self.file_path = file_path
        self.rules = rules
        self.global_context = global_context
        self.state = TaintState()
        self.findings: list[Finding] = []

        # Heriter le taint des fichiers inclus
        if global_context:
            inherited = global_context.get_included_taint(file_path)
            for var, fact in inherited.items():
                self.state.set_taint(var, fact)

    def analyze(self) -> list[Finding]:
        """Analyse l'AST complet et retourne les findings."""
        self._walk(self.tree.root_node)

        # Exporter le taint global
        if self.global_context:
            self.global_context.exported_taint[self.file_path] = dict(self.state.variables)

        return self.findings

    # --- AST Walking ---

    def _walk(self, node):
        """Parcours recursif avec dispatch par type de noeud."""
        handler = self._handlers.get(node.type)
        if handler:
            handler(self, node)
        else:
            # Continuer le parcours pour les noeuds non geres
            for child in node.children:
                self._walk(child)

    def _walk_children(self, node):
        for child in node.children:
            self._walk(child)

    # --- Handlers de statements ---

    def _handle_program(self, node):
        self._walk_children(node)

    def _handle_expression_statement(self, node):
        """Expression standalone (ex: appel de fonction)."""
        for child in node.named_children:
            self._walk(child)

    def _handle_assignment(self, node):
        """$x = <expr> : propager le taint du RHS vers le LHS."""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return

        var_key = self._text(left)
        rhs_taint = self._evaluate_taint(right)

        if rhs_taint and rhs_taint.is_tainted:
            new_fact = rhs_taint.derive(
                f"Assigned to {var_key}",
                file=self.file_path,
                line=node.start_point[0] + 1,
                snippet=self._line_snippet(node),
            )
            self.state.set_taint(var_key, new_fact)
        else:
            # Assignation clean -> retirer le taint
            self.state.remove_taint(var_key)

        # Verifier le RHS pour les sinks
        self._check_expression_sinks(right)

    def _handle_augmented_assignment(self, node):
        """$x .= <expr>, $x += <expr>, etc."""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return

        var_key = self._text(left)
        rhs_taint = self._evaluate_taint(right)
        existing = self.state.get_taint(var_key)

        if rhs_taint or existing:
            labels = set()
            filters = {}
            trace = []
            if existing:
                labels.update(existing.labels)
                filters.update(existing.filters_applied)
                trace = list(existing.trace)
            if rhs_taint:
                labels.update(rhs_taint.labels)
                filters.update(rhs_taint.filters_applied)
                if not trace:
                    trace = list(rhs_taint.trace)

            trace.append(TraceStep(
                file=self.file_path,
                line=node.start_point[0] + 1,
                description=f"Augmented assignment to {var_key}",
                snippet=self._line_snippet(node),
            ))
            self.state.set_taint(var_key, TaintFact(labels=labels, filters_applied=filters, trace=trace))

    def _handle_echo(self, node):
        """echo <expr> : sink XSS."""
        vuln_rule = self.rules.get_node_type_vuln("echo_statement")
        if not vuln_rule:
            return

        for child in node.named_children:
            taint = self._evaluate_taint(child)
            if taint and taint.is_dangerous_for("xss"):
                self._record_finding(
                    vuln_type="xss",
                    node=node,
                    sink_function="echo",
                    taint=taint,
                )
            self._check_expression_sinks(child)

    def _handle_include(self, node):
        """include/require <expr> : sink file_inclusion."""
        # L'expression est le deuxieme enfant (apres le mot-cle)
        expr_node = None
        for child in node.named_children:
            expr_node = child
            break

        if expr_node:
            taint = self._evaluate_taint(expr_node)
            if taint and taint.is_dangerous_for("file_inclusion"):
                keyword = node.children[0].type if node.children else "include"
                self._record_finding(
                    vuln_type="file_inclusion",
                    node=node,
                    sink_function=keyword.replace("_expression", ""),
                    taint=taint,
                )

    def _handle_function_call(self, node):
        """Appel de fonction : verifier sink, filter, propagator."""
        func_name = get_function_name(node, self.source_bytes)
        if not func_name:
            self._walk_children(node)
            return

        args = get_argument_nodes(node)

        # Verifier si c'est un sink
        vuln_rule = self.rules.get_sink_vuln(func_name)
        if vuln_rule:
            self._check_sink_args(node, func_name, vuln_rule, args)

        # Parcourir les arguments pour les sous-expressions
        for arg in args:
            self._check_expression_sinks(arg)

    def _handle_member_call(self, node):
        """$obj->method(args) : meme logique que function_call."""
        name_node = node.child_by_field_name("name")
        if name_node:
            method_name = self._text(name_node)
            args = get_argument_nodes(node)
            vuln_rule = self.rules.get_sink_vuln(method_name)
            if vuln_rule:
                self._check_sink_args(node, method_name, vuln_rule, args)
            for arg in args:
                self._check_expression_sinks(arg)

    def _handle_if(self, node):
        """if/else : cloner l'etat, analyser les branches, merge."""
        # Analyser la condition (peut contenir des assignations)
        cond = node.child_by_field_name("condition")
        if cond:
            self._check_expression_sinks(cond)

        # Sauvegarder l'etat
        pre_state = self.state.clone()

        # Branche then
        then_body = find_child_by_type(node, "compound_statement")
        if then_body:
            self._walk_children(then_body)
        then_state = self.state.clone()

        # Branche else
        self.state = pre_state.clone()
        else_clause = find_child_by_type(node, "else_clause")
        if else_clause:
            self._walk_children(else_clause)
        else_state = self.state

        # Merge union (conservatif)
        self.state = then_state.merge(else_state)

    def _handle_while(self, node):
        """while/for : 2 iterations pour taint loop-carried."""
        pre_state = self.state.clone()
        body = find_child_by_type(node, "compound_statement")
        if body:
            # Premiere iteration
            self._walk_children(body)
            # Deuxieme iteration (capture taint loop-carried)
            self._walk_children(body)
        self.state = pre_state.merge(self.state)

    def _handle_for(self, node):
        """for statement."""
        self._handle_while(node)

    def _handle_foreach(self, node):
        """foreach ($source as $key => $value) : propager le taint."""
        # Trouver la variable source et les variables d'iteration
        children = list(node.named_children)
        if not children:
            return

        # Evaluer la source (premier enfant nomme)
        source_node = children[0] if children else None
        if source_node:
            source_taint = self._evaluate_taint(source_node)

            # Trouver les variables d'iteration dans le foreach
            for child in node.children:
                if child.type == "pair":
                    # $key => $value
                    pair_children = list(child.named_children)
                    if len(pair_children) >= 2 and source_taint:
                        key_var = self._text(pair_children[0])
                        val_var = self._text(pair_children[1])
                        self.state.set_taint(val_var, source_taint.derive(
                            f"Foreach iteration value",
                            file=self.file_path, line=node.start_point[0] + 1
                        ))
                        self.state.set_taint(key_var, source_taint.derive(
                            f"Foreach iteration key",
                            file=self.file_path, line=node.start_point[0] + 1
                        ))
                elif child.type == "variable_name" and source_taint:
                    var_name = self._text(child)
                    # Eviter de tagger la source elle-meme
                    if var_name != self._text(source_node):
                        self.state.set_taint(var_name, source_taint.derive(
                            f"Foreach iteration",
                            file=self.file_path, line=node.start_point[0] + 1
                        ))

        # Analyser le corps
        body = find_child_by_type(node, "compound_statement")
        if body:
            self._walk_children(body)
            self._walk_children(body)  # 2eme iteration

    def _handle_return(self, node):
        """return <expr> : enregistrer le taint de retour."""
        if node.named_children:
            taint = self._evaluate_taint(node.named_children[0])
            if taint:
                self.state.set_taint("__return__", taint)

    def _handle_function_def(self, node):
        """function definition : analyser le corps dans un scope separe."""
        saved_state = self.state
        self.state = TaintState()

        # Les parametres sont clean par defaut
        params_node = node.child_by_field_name("parameters")
        if params_node:
            for param in params_node.named_children:
                if param.type == "simple_parameter":
                    var_node = find_child_by_type(param, "variable_name")
                    if var_node:
                        pass  # Parametres non tainted par defaut

        body = node.child_by_field_name("body")
        if body:
            self._walk_children(body)

        self.state = saved_state

    def _handle_method_def(self, node):
        """method_declaration : meme traitement que function_definition."""
        self._handle_function_def(node)

    def _handle_class(self, node):
        """class_declaration : analyser les methodes."""
        body = node.child_by_field_name("body")
        if body:
            self._walk_children(body)

    def _handle_switch(self, node):
        """switch : analyser tous les cases comme des branches, merge."""
        pre_state = self.state.clone()
        body = find_child_by_type(node, "switch_body")
        if body:
            self._walk_children(body)
        self.state = pre_state.merge(self.state)

    def _handle_try(self, node):
        """try/catch : analyser body et catch, merge."""
        pre_state = self.state.clone()
        self._walk_children(node)
        self.state = pre_state.merge(self.state)

    # --- Evaluation de taint d'expressions ---

    def _evaluate_taint(self, node) -> Optional[TaintFact]:
        """Evalue recursivement si une expression est tainted."""
        if node is None:
            return None

        ntype = node.type

        # Variable
        if ntype == "variable_name":
            var_name = self._text(node)
            return self.state.get_taint(var_name)

        # Acces tableau : $_GET['key'] ou $arr[$key]
        if ntype == "subscript_expression":
            return self._eval_subscript(node)

        # Expression binaire : concatenation, arithmetique
        if ntype == "binary_expression":
            return self._eval_binary(node)

        # String interpolation : "Hello $x"
        if ntype == "encapsed_string":
            return self._eval_encapsed(node)

        # Heredoc
        if ntype == "heredoc":
            return self._eval_heredoc(node)

        # Appel de fonction
        if ntype == "function_call_expression":
            return self._eval_function_call(node)

        # Appel de methode
        if ntype == "member_call_expression":
            return self._eval_method_call(node)

        # Cast : (int)$x, (string)$x
        if ntype == "cast_expression":
            return self._eval_cast(node)

        # Ternaire : $a ? $b : $c
        if ntype == "conditional_expression":
            body = node.child_by_field_name("body")
            alt = node.child_by_field_name("alternative")
            t_body = self._evaluate_taint(body)
            t_alt = self._evaluate_taint(alt)
            return self._merge_taints(t_body, t_alt, "Ternary expression")

        # Parentheses
        if ntype == "parenthesized_expression":
            if node.named_children:
                return self._evaluate_taint(node.named_children[0])

        # Assignation inline (dans une expression)
        if ntype == "assignment_expression":
            right = node.child_by_field_name("right")
            rhs_taint = self._evaluate_taint(right)
            left = node.child_by_field_name("left")
            if left and rhs_taint:
                self.state.set_taint(self._text(left), rhs_taint)
            return rhs_taint

        # Acces propriete : $obj->prop
        if ntype == "member_access_expression":
            key = self._text(node)
            return self.state.get_taint(key)

        # Creation de tableau : tainted si un element l'est
        if ntype in ("array_creation_expression", "list_literal"):
            return self._eval_array_creation(node)

        # Unaire : !$x, -$x
        if ntype == "unary_op_expression":
            if node.named_children:
                return self._evaluate_taint(node.named_children[0])

        # Litteraux : jamais tainted
        if ntype in ("string", "integer", "float", "boolean", "null", "nowdoc_string"):
            return None

        # Argument nomme
        if ntype == "argument":
            if node.named_children:
                return self._evaluate_taint(node.named_children[-1])

        return None

    def _eval_subscript(self, node) -> Optional[TaintFact]:
        """Evalue $_GET['key'] ou $arr[$i]."""
        full_text = self._text(node)

        # Verifier si c'est une source superglobale
        if node.children:
            base_text = self._text(node.children[0])
            if self.rules.is_source(base_text):
                return TaintFact(
                    labels={TaintLabel(
                        source_type="user_input",
                        source_var=full_text,
                        source_file=self.file_path,
                        source_line=node.start_point[0] + 1,
                        vuln_categories=ALL_VULN_CATEGORIES,
                    )},
                    trace=[TraceStep(
                        file=self.file_path,
                        line=node.start_point[0] + 1,
                        description=f"Source: {full_text}",
                        snippet=self._line_snippet(node),
                    )],
                )

            # Propagation depuis un tableau tainted
            base_taint = self.state.get_taint(base_text)
            if base_taint:
                return base_taint.derive(
                    f"Array access {full_text}",
                    file=self.file_path,
                    line=node.start_point[0] + 1,
                )

        # Verifier par cle specifique
        return self.state.get_taint(full_text)

    def _eval_binary(self, node) -> Optional[TaintFact]:
        """Evalue a . b, a + b, etc."""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        t_left = self._evaluate_taint(left)
        t_right = self._evaluate_taint(right)
        return self._merge_taints(t_left, t_right, "Binary expression")

    def _eval_encapsed(self, node) -> Optional[TaintFact]:
        """Evalue "Hello $x world"."""
        combined = None
        for child in node.named_children:
            t = self._evaluate_taint(child)
            combined = self._merge_taints(combined, t, "String interpolation")
        return combined

    def _eval_heredoc(self, node) -> Optional[TaintFact]:
        """Evalue heredoc avec variables interpolees."""
        combined = None
        for child in node.named_children:
            if child.type == "heredoc_body":
                for sub in child.named_children:
                    t = self._evaluate_taint(sub)
                    combined = self._merge_taints(combined, t, "Heredoc interpolation")
            else:
                t = self._evaluate_taint(child)
                combined = self._merge_taints(combined, t, "Heredoc interpolation")
        return combined

    def _eval_function_call(self, node) -> Optional[TaintFact]:
        """Evalue le taint d'un retour de fonction."""
        func_name = get_function_name(node, self.source_bytes)
        args = get_argument_nodes(node)

        # Source function
        if self.rules.is_source_function(func_name):
            return TaintFact(
                labels={TaintLabel(
                    source_type="function",
                    source_var=f"{func_name}()",
                    source_file=self.file_path,
                    source_line=node.start_point[0] + 1,
                    vuln_categories=ALL_VULN_CATEGORIES,
                )},
                trace=[TraceStep(
                    file=self.file_path,
                    line=node.start_point[0] + 1,
                    description=f"Source: {func_name}()",
                    snippet=self._line_snippet(node),
                )],
            )

        # Filtre/sanitizer
        filter_info = self.rules.get_filter_info(func_name)
        if filter_info and args:
            arg_taint = self._evaluate_taint(args[0])
            if arg_taint:
                return arg_taint.apply_filter(func_name, filter_info.neutralizes)
            return None

        # Propagateur
        if self.rules.is_propagator(func_name) and args:
            arg_taints = [self._evaluate_taint(a) for a in args]
            combined = None
            for t in arg_taints:
                combined = self._merge_taints(combined, t, f"Propagated through {func_name}()")
            return combined

        # Fonction user-defined (inter-procedural basique)
        if self.global_context:
            summary = self.global_context.get_function_summary(func_name)
            if summary:
                for param_idx, propagates in summary.param_to_return.items():
                    if propagates and param_idx < len(args):
                        arg_taint = self._evaluate_taint(args[param_idx])
                        if arg_taint:
                            return arg_taint.derive(f"Through {func_name}() param #{param_idx}")

        # Fonction inconnue : conservatif - si un arg est tainted, retour possiblement tainted
        arg_taints = [self._evaluate_taint(a) for a in args]
        for t in arg_taints:
            if t and t.is_tainted:
                return t.derive(f"Through unknown function {func_name}()")

        return None

    def _eval_method_call(self, node) -> Optional[TaintFact]:
        """Evalue $obj->method(args)."""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None

        method_name = self._text(name_node)
        args = get_argument_nodes(node)

        # Verifier si c'est un filtre ou propagateur
        filter_info = self.rules.get_filter_info(method_name)
        if filter_info and args:
            arg_taint = self._evaluate_taint(args[0])
            if arg_taint:
                return arg_taint.apply_filter(method_name, filter_info.neutralizes)
            return None

        # Conservatif : propager si un arg est tainted
        arg_taints = [self._evaluate_taint(a) for a in args]
        for t in arg_taints:
            if t and t.is_tainted:
                return t.derive(f"Through method {method_name}()")

        # Verifier si l'objet lui-meme est tainted
        obj_node = node.child_by_field_name("object")
        if obj_node:
            obj_taint = self._evaluate_taint(obj_node)
            if obj_taint:
                return obj_taint.derive(f"Method call {method_name}() on tainted object")

        return None

    def _eval_cast(self, node) -> Optional[TaintFact]:
        """Evalue (int)$x, (string)$x."""
        type_node = node.child_by_field_name("type")
        value_node = node.child_by_field_name("value")
        if not value_node:
            return None

        value_taint = self._evaluate_taint(value_node)
        if not value_taint:
            return None

        if type_node:
            cast_type = self._text(type_node).strip("()")
            cast_key = f"_cast_{cast_type}"
            filter_info = self.rules.get_filter_info(cast_key)
            if filter_info:
                return value_taint.apply_filter(cast_key, filter_info.neutralizes)

        return value_taint

    def _eval_array_creation(self, node) -> Optional[TaintFact]:
        """Tainted si un element est tainted."""
        combined = None
        for child in node.named_children:
            t = self._evaluate_taint(child)
            combined = self._merge_taints(combined, t, "Array element")
        return combined

    # --- Verification des sinks dans les expressions ---

    def _check_expression_sinks(self, node):
        """Parcours recursif pour trouver les sinks dans une expression."""
        if node is None:
            return

        if node.type == "function_call_expression":
            self._handle_function_call(node)
            return

        if node.type == "member_call_expression":
            self._handle_member_call(node)
            return

        for child in node.named_children:
            self._check_expression_sinks(child)

    def _check_sink_args(self, node, func_name: str, vuln_rule, args: list):
        """Verifie si les arguments d'un sink sont tainted."""
        for arg in args:
            taint = self._evaluate_taint(arg)
            if taint and taint.is_dangerous_for(vuln_rule.vuln_type):
                self._record_finding(
                    vuln_type=vuln_rule.vuln_type,
                    node=node,
                    sink_function=func_name,
                    taint=taint,
                )
                return  # Un finding par appel de fonction

    # --- Recording des findings ---

    def _record_finding(self, vuln_type: str, node, sink_function: str, taint: TaintFact):
        """Cree et enregistre un Finding."""
        vuln_rule = self.rules.vulnerabilities.get(vuln_type)
        if not vuln_rule:
            return

        # Determiner la confiance
        confidence = Confidence.HIGH
        if not taint.trace:
            confidence = Confidence.LOW
        elif len(taint.trace) == 1:
            confidence = Confidence.MEDIUM

        # Verifier les sanitizers contextuels
        remaining = taint.remaining_categories()
        if vuln_type not in remaining:
            return  # Sanitise correctement

        # Source variable
        source_var = ""
        if taint.labels:
            source_var = next(iter(taint.labels)).source_var

        # Ajouter le step final (sink)
        trace = list(taint.trace)
        trace.append(TraceStep(
            file=self.file_path,
            line=node.start_point[0] + 1,
            description=f"Reaches {sink_function}() sink",
            snippet=self._line_snippet(node),
        ))

        self.findings.append(Finding(
            vuln_type=vuln_type,
            severity=vuln_rule.severity,
            confidence=confidence,
            cwe=vuln_rule.cwe,
            owasp=vuln_rule.owasp,
            title=f"{vuln_type.replace('_', ' ').title()} in {sink_function}()",
            description=vuln_rule.description,
            file_path=self.file_path,
            line=node.start_point[0] + 1,
            column=node.start_point[1],
            sink_function=sink_function,
            source_variable=source_var,
            code_snippet=self._line_snippet(node),
            data_flow=trace,
            remediation=vuln_rule.remediation,
            detection_mode="taint",
        ))

    # --- Helpers ---

    def _text(self, node) -> str:
        return get_node_text(node, self.source_bytes)

    def _line_snippet(self, node) -> str:
        line_idx = node.start_point[0]
        lines = self.source.splitlines()
        if 0 <= line_idx < len(lines):
            return lines[line_idx].strip()
        return ""

    def _merge_taints(
        self, a: Optional[TaintFact], b: Optional[TaintFact], description: str
    ) -> Optional[TaintFact]:
        """Merge deux TaintFacts (union)."""
        if a is None:
            return b
        if b is None:
            return a
        labels = a.labels | b.labels
        filters = {**a.filters_applied, **b.filters_applied}
        trace = a.trace if len(a.trace) >= len(b.trace) else b.trace
        trace = list(trace)
        if description:
            trace.append(TraceStep(
                file=self.file_path,
                line=trace[-1].line if trace else 0,
                description=description,
            ))
        return TaintFact(labels=labels, filters_applied=filters, trace=trace)

    # --- Dispatch table ---

    _handlers = {
        "program": _handle_program,
        "expression_statement": _handle_expression_statement,
        "assignment_expression": _handle_assignment,
        "augmented_assignment_expression": _handle_augmented_assignment,
        "echo_statement": _handle_echo,
        "include_expression": _handle_include,
        "require_expression": _handle_include,
        "include_once_expression": _handle_include,
        "require_once_expression": _handle_include,
        "function_call_expression": _handle_function_call,
        "member_call_expression": _handle_member_call,
        "if_statement": _handle_if,
        "while_statement": _handle_while,
        "for_statement": _handle_for,
        "foreach_statement": _handle_foreach,
        "switch_statement": _handle_switch,
        "try_statement": _handle_try,
        "return_statement": _handle_return,
        "function_definition": _handle_function_def,
        "method_declaration": _handle_method_def,
        "class_declaration": _handle_class,
        "compound_statement": _handle_program,  # bloc {}
    }
