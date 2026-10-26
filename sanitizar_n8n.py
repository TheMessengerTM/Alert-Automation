"""
Sanitiza fluxos exportados do n8n para publicação no GitHub.

Uso:
    python sanitizar_n8n.py                 # lê ./exportados  -> grava ./workflows
    python sanitizar_n8n.py ENTRADA SAIDA   # pastas personalizadas

O que é removido/substituído:
  - Referências de credenciais (id e nome) em cada nó
  - IDs da instância, versão, projeto, compartilhamento e dados fixados (pinData)
  - Dados estáticos (staticData) e webhookIds
  - Campos com nomes sensíveis (token, apiKey, password, secret, authorization...)
  - Cabeçalhos/query params sensíveis (Authorization, X-API-Key...)
  - Padrões de segredo em qualquer texto, inclusive em nós de código
    (JWT, Bearer, chaves OpenAI/GitHub/AWS/Google/Slack, user:senha@ em URLs, ?token=...)
  - E-mails, telefones, CPF/CNPJ e IPs privados
  - IDs de planilhas/documentos/pastas/chats (resource locators)
Ao final é exibido um relatório com o que foi alterado e pontos para revisão manual.
"""

import json
import re
import sys
from pathlib import Path

PH = "<<PREENCHER>>"

# Chaves no topo do workflow que identificam a instância/conta ou trazem dados reais
TOP_LEVEL_REMOVE = {
    "id", "versionId", "activeVersionId", "activeVersion", "pinData", "staticData",
    "shared", "homeProject", "scopes", "usedCredentials", "sharedWithProjects",
    "triggerCount", "createdAt", "updatedAt", "isArchived", "parentFolder",
}

# Chaves de nó a remover
NODE_REMOVE = {"webhookId"}

# Nome de campo que indica valor sensível
SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|senha|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|authorization|auth[_-]?header|bearer|"
    r"cookie|session|signature|webhook[_-]?secret|x-api-key)",
    re.I,
)

# Campos de "nome/valor" (headers, query, body) cujo nome é sensível
NAME_VALUE_KEYS = ("name", "key", "parameterName")

# Resource locators / IDs de recursos externos
ID_KEYS = re.compile(
    r"^(documentId|sheetId|spreadsheetId|folderId|fileId|driveId|calendarId|"
    r"chatId|channelId|guildId|baseId|tableId|databaseId|pageId|boardId|listId|"
    r"projectId|workspaceId|phoneNumberId|businessAccountId|recipientPhoneNumber|"
    r"accountId|siteId|teamId|userId|formId|surveyId)$"
)

SECRET_PATTERNS = [
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("Bearer", re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]{12,}=*")),
    ("Basic", re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/]{12,}=*")),
    ("OpenAI/Anthropic", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("GitHub", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Telegram bot", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("Stripe", re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{16,}")),
    ("URL c/ usuário:senha", re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)")),
    ("Query string secreta", re.compile(
        r"(?i)([?&](?:api[_-]?key|apikey|token|access_token|key|secret|password|sig|signature)=)[^&\s\"']+")),
    ("Atribuição secreta em código", re.compile(
        r"(?i)((?:api[_-]?key|apikey|token|secret|password|senha|authorization)\s*[:=]\s*['\"`])"
        r"(?!\{\{|\$)[^'\"`\s]{6,}(['\"`])")),
]

PII_PATTERNS = [
    ("E-mail", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "exemplo@exemplo.com"),
    ("CNPJ", re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"), "00.000.000/0000-00"),
    ("CPF", re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), "000.000.000-00"),
    ("Telefone", re.compile(r"(?<![\w.])(?:\+?55\s?)?\(?\d{2}\)?\s?9?\d{4}[-\s]?\d{4}(?![\w.])"), "5511999999999"),
    ("IP privado", re.compile(
        r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2,3}\b"), "127.0.0.1"),
]

# Domínios que não são considerados sensíveis no relatório de revisão
PUBLIC_DOMAINS = re.compile(
    r"(n8n\.io|googleapis\.com|google\.com|openai\.com|anthropic\.com|github\.com|"
    r"api\.telegram\.org|graph\.facebook\.com|slack\.com|microsoft\.com|"
    r"office\.com|notion\.com|example\.com|exemplo\.com)", re.I)

URL_RE = re.compile(r"https?://[^\s\"'`<>]+")


class Report:
    def __init__(self):
        self.items = []
        self.review = set()

    def add(self, where, what):
        self.items.append(f"{where}: {what}")


def scrub_text(text, where, rep):
    if not isinstance(text, str) or not text:
        return text
    for label, rx in SECRET_PATTERNS:
        def _sub(m, label=label):
            rep.add(where, f"segredo removido ({label})")
            if m.lastindex and m.lastindex >= 2:
                return m.group(1) + PH + m.group(m.lastindex)
            if m.lastindex:
                return m.group(1) + PH
            return PH
        text = rx.sub(_sub, text)
    for label, rx, repl in PII_PATTERNS:
        def _sub_pii(m, label=label, repl=repl):
            if m.group(0) == repl:
                return repl
            rep.add(where, f"{label} substituído")
            return repl
        text = rx.sub(_sub_pii, text)
    for url in URL_RE.findall(text):
        if not PUBLIC_DOMAINS.search(url) and "{{" not in url:
            rep.review.add(f"{where}: URL → {url[:100]}")
    return text


def is_expression(v):
    return isinstance(v, str) and v.strip().startswith("=") and "{{" in v


def scrub(obj, where, rep, parent_key=""):
    if isinstance(obj, dict):
        # Par nome/valor (ex.: headers) com nome sensível
        for nk in NAME_VALUE_KEYS:
            n = obj.get(nk)
            if isinstance(n, str) and SENSITIVE_KEY.search(n) and "value" in obj:
                if isinstance(obj["value"], str) and obj["value"] and not is_expression(obj["value"]):
                    rep.add(where, f"valor do campo '{n}' removido")
                    obj["value"] = PH
            # Parâmetros de ID da conta (ruleId, triggerIds, accountId...)
            elif isinstance(n, str) and re.search(r"(Ids?|_ids?)$", n) and "value" in obj \
                    and isinstance(obj["value"], str) and obj["value"] and not is_expression(obj["value"]):
                rep.add(where, f"ID '{n}' removido")
                obj["value"] = PH
        # Resource locator {__rl, value, mode, cachedResultName, cachedResultUrl}
        if obj.get("__rl"):
            if obj.get("cachedResultUrl"):
                obj["cachedResultUrl"] = ""
            if obj.get("cachedResultName") and ID_KEYS.match(parent_key or ""):
                obj["cachedResultName"] = ""
            if ID_KEYS.match(parent_key or "") and isinstance(obj.get("value"), str) \
                    and obj["value"] and not is_expression(obj["value"]):
                rep.add(where, f"ID de recurso '{parent_key}' removido")
                obj["value"] = PH
        for k, v in list(obj.items()):
            if isinstance(v, str):
                if SENSITIVE_KEY.search(k) and v and not is_expression(v) and k not in ("authentication", "genericAuthType", "nodeCredentialType"):
                    rep.add(where, f"campo '{k}' removido")
                    obj[k] = PH
                elif ID_KEYS.match(k) and v and not is_expression(v):
                    rep.add(where, f"ID '{k}' removido")
                    obj[k] = PH
                else:
                    obj[k] = scrub_text(v, where, rep)
            else:
                scrub(v, where, rep, k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                obj[i] = scrub_text(v, where, rep)
            else:
                scrub(v, where, rep, parent_key)
    return obj


def sanitize_workflow(wf, rep):
    for k in TOP_LEVEL_REMOVE:
        wf.pop(k, None)
    wf["active"] = False
    meta = wf.get("meta")
    if isinstance(meta, dict):
        meta.pop("instanceId", None)
        if not meta:
            wf.pop("meta")
    if "tags" in wf and isinstance(wf["tags"], list):
        wf["tags"] = [{"name": t["name"]} if isinstance(t, dict) and "name" in t else t for t in wf["tags"]]
    settings = wf.get("settings")
    if isinstance(settings, dict):
        for k in ("errorWorkflow", "callerIds"):
            if settings.pop(k, None) is not None:
                rep.add("settings", f"'{k}' removido")

    for node in wf.get("nodes", []):
        name = node.get("name", "?")
        for k in NODE_REMOVE:
            node.pop(k, None)
        creds = node.get("credentials")
        if isinstance(creds, dict) and creds:
            for ctype in creds:
                creds[ctype] = {"name": f"<<CRIAR CREDENCIAL {ctype}>>"}
            rep.add(f"nó '{name}'", f"credencial(is) desvinculada(s): {', '.join(creds)}")
        params = node.get("parameters", {})
        # Webhook: o path costuma ser um UUID que expõe a URL pública
        if node.get("type", "").endswith(".webhook") or node.get("type", "").endswith("Trigger"):
            p = params.get("path")
            if isinstance(p, str) and re.fullmatch(r"[0-9a-f-]{32,36}", p):
                params["path"] = "meu-webhook"
                rep.add(f"nó '{name}'", "path do webhook trocado")
        scrub(params, f"nó '{name}'", rep)
        if "notes" in node:
            node["notes"] = scrub_text(node["notes"], f"nó '{name}' (notas)", rep)
    return wf


def safe_filename(name):
    s = re.sub(r"[^\w\- ]", "", name, flags=re.UNICODE).strip().replace(" ", "_")
    return s or "workflow"


def load_workflows(path):
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    # Export de vários fluxos (n8n export:workflow --all) vem como lista
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "nodes" in data:
        return [data]
    if isinstance(data, dict) and isinstance(data.get("data"), list):  # resposta da API
        return data["data"]
    return []


def main():
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "exportados")
    dst = Path(sys.argv[2] if len(sys.argv) > 2 else "workflows")
    if not src.exists():
        src.mkdir(parents=True)
        print(f"Pasta '{src}' criada. Coloque nela os JSON exportados do n8n e rode de novo.")
        return
    dst.mkdir(parents=True, exist_ok=True)

    files = sorted(src.rglob("*.json"))
    if not files:
        print(f"Nenhum .json encontrado em '{src}'.")
        return

    total_review = []
    used = set()
    for f in files:
        try:
            wfs = load_workflows(f)
        except Exception as e:
            print(f"[ERRO] {f.name}: {e}")
            continue
        if not wfs:
            print(f"[IGNORADO] {f.name}: não parece ser um fluxo do n8n")
            continue
        for wf in wfs:
            rep = Report()
            sanitize_workflow(wf, rep)
            base = safe_filename(wf.get("name") or f.stem)
            out_name, i = base, 2
            while out_name in used:
                out_name, i = f"{base}_{i}", i + 1
            used.add(out_name)
            out = dst / f"{out_name}.json"
            out.write_text(json.dumps(wf, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"\n[OK] {wf.get('name')} -> {out}")
            for item in dict.fromkeys(rep.items):
                print(f"     - {item}")
            total_review += [f"{wf.get('name')} | {r}" for r in sorted(rep.review)]

    if total_review:
        print("\n=== REVISAR MANUALMENTE (URLs de domínios próprios/privados) ===")
        for r in total_review:
            print(f"  ! {r}")
    print("\nPronto. Revise os arquivos em", dst, "antes de fazer o commit.")


if __name__ == "__main__":
    main()
