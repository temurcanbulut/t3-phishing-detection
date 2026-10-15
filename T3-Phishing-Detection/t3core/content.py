"""HTML5 parsing as data; never executes scripts or submits forms."""

import json
import time
from collections import deque
from urllib.parse import urljoin, urlsplit

import html5lib
import idna
from html5lib._tokenizer import HTMLTokenizer
from html5lib.constants import _ReparseException, tagTokenTypes, tokenTypes

MAX_FORMS, MAX_NODES, MAX_CONTROLS = 50, 12000, 1000


class ContentLimit(ValueError):
    pass


class BoundedTokenizer(HTMLTokenizer):
    """Guard tokenizer states, including a single tag with many attributes.

    The adapter follows html5lib 1.1's tokenizer protocol; the dependency is
    pinned and its MIT notice is retained in THIRD_PARTY_NOTICES.txt.
    """

    def __iter__(self):
        self.tokenQueue = deque()
        emitted = 0
        while True:
            if time.monotonic() > self.parser.parse_deadline:
                raise ContentLimit("HTML tokenizer time budget reached")
            token = self.currentToken
            if token and token["type"] in tagTokenTypes and len(token.get("data", ())) > 256:
                raise ContentLimit("HTML tag attribute budget reached")
            if not self.state():
                break
            while self.stream.errors:
                if emitted >= 24000:
                    raise ContentLimit("HTML token budget reached")
                yield {"type": tokenTypes["ParseError"], "data": self.stream.errors.pop(0)}
                emitted += 1
            while self.tokenQueue:
                emitted += 1
                if emitted > 24000:
                    raise ContentLimit("HTML token budget reached")
                yield self.tokenQueue.popleft()


class BoundedParser(html5lib.HTMLParser):
    def _parse(self, stream, innerHTML=False, container="div", scripting=False, **options):
        self.parse_deadline = time.monotonic() + 0.5
        self.innerHTMLMode, self.container, self.scripting = innerHTML, container, scripting
        self.tokenizer = BoundedTokenizer(stream, parser=self, **options)
        self.reset()
        try:
            self.mainLoop()
        except _ReparseException:
            self.reset()
            self.mainLoop()


class BoundedTree(html5lib.getTreeBuilder("etree")):
    """Stop deep/large trees while parsing, before expensive postprocessing."""

    def reset(self):
        self.node_count = 0
        self.deadline = time.monotonic() + 0.5
        return super().reset()

    def guard(self, node=False):
        self.node_count += int(node)
        if (
            self.node_count > MAX_NODES
            or len(self.openElements) > 128
            or time.monotonic() > self.deadline
        ):
            raise ContentLimit("HTML parser node/depth/time budget reached")

    def createElement(self, token):
        self.guard(True)
        return super().createElement(token)

    def insertElementNormal(self, token):
        self.guard(True)
        return super().insertElementNormal(token)

    def insertText(self, data, parent=None):
        self.guard()
        return super().insertText(data, parent)

    def insertComment(self, token, parent=None):
        self.guard(True)
        return super().insertComment(token, parent)


def resolve_action(base, raw, document_url):
    try:
        if raw and ("\\" in raw or any(ord(x) < 32 for x in raw)):
            return str(raw)[:4096], None
        action = urljoin(base, raw) if raw else document_url
        if len(action) > 4096:
            return action[:4096], None
        parsed = urlsplit(action)
        _port = parsed.port
        return action[:4096], parsed
    except ValueError:
        return str(raw)[:4096], None


def comparable_host(host):
    if not host:
        return None
    try:
        return idna.encode(host.rstrip("."), uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError:
        return host.lower()


def extract_page(html, url, *, transport_encoding=None, truncated=False):
    parser = BoundedParser(tree=BoundedTree, namespaceHTMLElements=False)
    options = {"transport_encoding": transport_encoding} if isinstance(html, bytes) else {}
    try:
        document = parser.parse(html[:131072], **options)
    except ContentLimit as error:
        return dict(
            title="",
            forms=[],
            script_elements=None,
            parser="html5lib HTML5",
            encoding=parser.documentEncoding,
            limited=True,
            limit_reason=str(error),
            scope="HTML parsing stopped at node/depth/time budget; no complete page facts available.",
        ), []
    parents, elements, stack = {}, [], [document]
    limited = truncated or len(html) > 131072
    while stack:
        element = stack.pop()
        elements.append(element)
        if len(elements) >= MAX_NODES:
            limited = True
            break
        if element.tag == "template":
            continue
        for child in reversed(list(element)):
            parents[child] = element
            stack.append(child)
    base = url
    for element in elements:
        if element.tag == "base" and element.get("href") is not None:
            base, parsed = resolve_action(url, element.get("href"), url)
            if parsed is None or parsed.scheme not in ("http", "https") or not parsed.hostname:
                base = url
                limited = True
            break
    forms = [e for e in elements if e.tag == "form"]
    limited |= len(forms) > MAX_FORMS
    forms = forms[:MAX_FORMS]
    facts, id_owners = {}, {}
    remaining_facts = 60000

    def reserve_fact(value):
        nonlocal remaining_facts
        cost = len(json.dumps(value, ensure_ascii=True)) + 16
        if cost > remaining_facts:
            return False
        remaining_facts -= cost
        return True

    for element in elements:
        if element.get("id"):
            id_owners.setdefault(element.get("id"), element)
    for element in forms:
        action, _parsed = resolve_action(base, element.get("action"), url)
        limited |= _parsed is None and len(action) >= 4096
        method = element.get("method", "get").lower()
        entry = dict(
            id=element.get("id", "")[:200],
            action=action,
            method=method if method in ("get", "post", "dialog") else "get",
            password_fields=0,
            disabled_password_fields=0,
            submit_overrides=[],
        )
        if reserve_fact(entry):
            facts[element] = entry
        else:
            limited = True
    controls = 0
    for element in elements:
        if element.tag not in ("input", "button"):
            continue
        controls += 1
        if controls > MAX_CONTROLS:
            limited = True
            break
        owner = None
        if element.get("form") is not None:
            candidate = id_owners.get(element.get("form"))
            if candidate in facts:
                owner = candidate
        else:
            current = parents.get(element)
            while current is not None:
                if current.tag == "form":
                    owner = current if current in facts else None
                    break
                current = parents.get(current)
        if owner is None:
            continue
        entry = facts[owner]
        disabled = "disabled" in element.attrib
        current = parents.get(element)
        while current is not None:
            if current.tag == "fieldset" and "disabled" in current.attrib:
                first_legend = next((c for c in current if c.tag == "legend"), None)
                ancestor, in_legend = element, False
                while ancestor is not None and ancestor is not current:
                    in_legend |= ancestor is first_legend
                    ancestor = parents.get(ancestor)
                disabled |= not in_legend
            current = parents.get(current)
        kind = element.get("type", "submit" if element.tag == "button" else "text").lower()
        if element.tag == "button" and kind not in ("submit", "reset", "button"):
            kind = "submit"
        if element.tag == "input" and kind == "password":
            entry["password_fields"] += 1
            entry["disabled_password_fields"] += int(disabled)
        if (
            not disabled
            and kind in ("submit", "image")
            and ("formaction" in element.attrib or "formmethod" in element.attrib)
        ):
            action, _parsed = (
                resolve_action(base, element.get("formaction"), url)
                if "formaction" in element.attrib
                else (entry["action"], None)
            )
            method = element.get("formmethod", entry["method"]).lower()
            limited |= _parsed is None and len(action) >= 4096
            override = dict(
                action=action, method=method if method in ("get", "post", "dialog") else "get"
            )
            if override not in entry["submit_overrides"]:
                if reserve_fact(override):
                    entry["submit_overrides"].append(override)
                else:
                    limited = True
    findings, seen = [], set()
    remaining_findings = 60000
    for entry in facts.values():
        if entry["password_fields"] <= entry["disabled_password_fields"]:
            continue
        for submission in [entry, *entry["submit_overrides"]]:
            if submission["method"] == "dialog":
                continue
            action, parsed = resolve_action(url, submission["action"], url)
            reasons = []
            if parsed is None:
                reasons.append(
                    (
                        "credential_form_invalid_action",
                        "Parola alanlı form çözümlenemeyen bir gönderim hedefi belirtiyor.",
                    )
                )
            else:
                if parsed.scheme != "https":
                    reasons.append(
                        (
                            "credential_form_non_https",
                            "Parola alanlı form HTTPS dışı bir hedef belirtiyor.",
                        )
                    )
                if (
                    parsed.scheme in ("http", "https")
                    and parsed.hostname
                    and comparable_host(parsed.hostname) != comparable_host(urlsplit(url).hostname)
                ):
                    reasons.append(
                        (
                            "credential_form_cross_host",
                            "Parola alanlı form farklı bir ana makineye gönderim belirtiyor. Bu tek başına phishing kanıtı değildir.",
                        )
                    )
            for kind, detail in reasons:
                if (kind, action) not in seen:
                    seen.add((kind, action))
                    finding = dict(
                        kind=kind,
                        detail=detail,
                        evidence=dict(
                            action=action, method=submission["method"], form_id=entry["id"]
                        ),
                    )
                    cost = len(json.dumps(finding, ensure_ascii=True)) + 16
                    if cost <= remaining_findings:
                        remaining_findings -= cost
                        findings.append(finding)
                    else:
                        limited = True
    title = next(("".join(e.itertext()).strip()[:300] for e in elements if e.tag == "title"), "")
    uncertain_form_tree = bool(facts) and any(
        "table" in code for _position, code, _data in parser.errors
    )
    limited |= uncertain_form_tree
    return dict(
        title=title,
        forms=list(facts.values()),
        script_elements=sum(e.tag == "script" for e in elements),
        parser="html5lib HTML5; source HTML only",
        encoding=parser.documentEncoding,
        limited=limited,
        form_association_uncertain=uncertain_form_tree,
        scope="Static form declarations and submit overrides; JavaScript, shadow DOM and custom-element behavior are not executed.",
    ), findings
