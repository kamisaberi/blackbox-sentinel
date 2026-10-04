---

### File: `blackbox-sentinel/docs/subsystems-26/web-application/05-waf.md`

```markdown
# Subsystem 05: Web Application & API Protection (`05_waf`)

`05_waf` inspects incoming HTTP/1.1, HTTP/2, and REST/JSON API transactions, defending web services and embedded management consoles from OWASP Top 10 vulnerabilities (SQLi, XSS, SSRF, and BOLA/IDOR).

---

## 1. Zero-Copy HTTP Stream Vectorization

`05_waf` tokenizes URI paths, headers, and request bodies using an internal parser that avoids copying strings onto the heap:

```text
 [ HTTP POST /api/v1/telemetry?query=SELECT%20* HTTP/1.1 ]
                           │
                           ▼ In-Place Tokenizer
 ┌─────────────────────────────────────────────────────────────┐
 │ 1. Decodes Percent-Encoding in-place                        │
 │ 2. Strips Whitespace & Comment Injection                    │
 │ 3. Computes Character Entropy (Shannon)                     │
 │ 4. Evaluates SQL Grammar AST (Abstract Syntax Tree) Nodes   │
 └─────────────────────────┬───────────────────────────────────┘
                           │
                           ▼ Malicious SQL Pattern Confirmed
 [ In-Kernel XDP Block Triggered: Source IP Dropped (< 0.84 µs) ]
```

---

## 2. Broken Object Level Authorization (BOLA/IDOR) Engine

`05_waf` tracks authorization contexts across API invocations:
* If User Token $A$ accesses `/api/v1/tenant/101/status` and subsequently requests `/api/v1/tenant/102/status` without a credential switch, an IDOR violation is flagged and the session is terminated.
```

