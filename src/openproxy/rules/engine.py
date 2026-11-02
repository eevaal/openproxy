from urllib.parse import parse_qs

from openproxy.rules.models import Rule, normalize_host


def select_rule(
    rules: list[Rule], method: str, host: str, path: str, query: str
) -> Rule | None:
    parameters = parse_qs(query, keep_blank_values=True)
    for rule in sorted(rules, key=lambda item: -item.priority):
        match = rule.match
        if (
            rule.enabled
            and (match.method is None or match.method == method)
            and (
                match.host is None or normalize_host(match.host) == normalize_host(host)
            )
            and (match.path is None or match.path == path)
            and all(parameters.get(k) == [v] for k, v in match.query.items())
        ):
            return rule
    return None
