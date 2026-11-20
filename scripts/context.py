#!/usr/bin/env python3
"""Business context for a scan: who owns each system, how long its data must stay confidential, how long
migration takes, and how much it matters (schema fedlin.pqc-context 1.1, schemas/context-1.1.schema.json).

Context never changes a verdict or a priority label. It adds two things:
  attention order   endpoints ranked by the severity of their worst finding and their FIPS 199 impact, with
                    owners (score = impact x severity; ties go to the worse finding, then the higher impact);
  urgency flag      for endpoints exposed to harvest-now-decrypt-later recording, Mosca's inequality with a
                    planning horizon standing in for the time to a cryptographically relevant quantum computer:
                    if the scan year plus the data's confidentiality lifetime plus the migration time reaches
                    past the horizon, the data must stay confidential beyond the date policy retires these
                    algorithms. That is what "urgent" means; it is not a prediction that the data will be
                    decrypted then.

Exposure per endpoint is one of:
  exposed       the negotiated key exchange is quantum-vulnerable, or the server accepts classical key
                exchange from clients that do not offer ML-KEM (a classical group or key-exchange suite
                accepted, TLS 1.2 or older accepted, or a classical-only client accepted);
  not exposed   ML-KEM negotiated and a complete enumeration and the classical-only probe show no classical
                key exchange accepted;
  undetermined  anything else (key exchange not observed or not classified, or acceptance not enumerated).
Only exposed endpoints get an urgency verdict; undetermined ones say so.

The horizon is a policy date, not a forecast. Each system gets one: 2030 for a system of FIPS 199 high impact or
marked a high-value asset (NIST IR 8547 and OMB M-26-15: post-quantum key establishment by the end of 2030), else
2035 (civilian: NIST IR 8547 disallows quantum-vulnerable signature and key-establishment schemes after 2035, all
of them deprecated after 2030; nss: the NSM-10 goal of 2035, with CNSA 2.0 requiring exclusive use earlier, 2030
to 2033, for several categories). A context file's "horizon" overrides both for every system (1.7.0; before,
every system used 2035 unless the file set its own). When a system gives no migration time, urgency uses the data lifetime alone
and says so: understated, never invented.

Systems match endpoints by pattern: a host glob (*.pay.example.gov; "*" also crosses dots), host:port, an IP
network (10.2.0.0/16), or an IP network with port (10.2.0.0/16:8443, [2001:db8::/32]:8443; IPv6 needs
brackets to carry a port). IP networks match endpoints scanned by address only. An endpoint matching several
systems takes the most demanding values (highest impact, longest lifetime, longest migration) and lists every
owner; endpoints no system matches are listed as "no context", and systems that match nothing are listed too.

Schema 1.1 (1.7.0) adds the optional system key "highValueAsset" (true/false); 1.0 files are still read.

Usage:  python3 scripts/context.py rank --context context.json --cbom cbom.json [--profile civilian|nss] [--json OUT]
Exit codes: 0 success, 2 invalid input.
"""
import argparse
import fnmatch
import ipaddress
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling modules, also under python -I
import cnsa20_ruleset as cnsa  # noqa: E402
import evidence as evmod  # noqa: E402
import wave as wavemod  # noqa: E402

SCHEMA, SCHEMA_VERSION = "fedlin.pqc-context", "1.1"
SCHEMA_VERSIONS = ("1.0", "1.1")
RESULT, RESULT_VERSION = "fedlin.pqc-attention", "1.0"
DEFAULT_HORIZON = 2035
HIGH_IMPACT_HORIZON = 2030
HIGH_IMPACT_SOURCE = "NIST IR 8547 and OMB M-26-15: post-quantum key establishment by 2030-12-31"
HORIZON_SOURCE = {
    "civilian": "NIST IR 8547: quantum-vulnerable signature and key-establishment schemes disallowed after 2035 "
                "(all deprecated after 2030)",
    "nss": "NSM-10 goal of 2035; CNSA 2.0 requires exclusive use earlier (2030 to 2033) for several categories",
}
IMPACT = {"low": 1, "moderate": 2, "high": 3}          # FIPS 199 impact levels
SEVERITY = {"Critical": 4, "High": 3, "Review": 2, "Low": 1}   # Review (unclassified) ranks above Low
TOP_KEYS = {"schema", "schemaVersion", "horizon", "systems"}
SYSTEM_KEYS = {"name", "owner", "impact", "dataLifetimeYears", "migrationYears", "endpoints"}
SYSTEM_KEYS_11 = SYSTEM_KEYS | {"highValueAsset"}
OLD_TLS = {"SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1", "TLSv1.2"}


class ContextError(ValueError):
    pass


def _year(v):
    return isinstance(v, int) and not isinstance(v, bool)


def load_context(path, redact=()):
    """Read and validate a context file. redact: (old, new) pairs applied to its text first, as --redact
    applies them to the CBOM, so patterns match the redacted CBOM and the given strings in names and owners are
    replaced too (only those strings)."""
    try:
        with open(path) as f:
            text = f.read()
        for old, new in redact:
            text = text.replace(old, new)
        c = json.loads(text)
    except (OSError, ValueError, RecursionError) as e:
        raise ContextError(f"{path}: {str(e)[:160]}")
    if not isinstance(c, dict) or c.get("schema") != SCHEMA or c.get("schemaVersion") not in SCHEMA_VERSIONS:
        raise ContextError(f"{path}: not a {SCHEMA} {' or '.join(SCHEMA_VERSIONS)} file")
    allowed = SYSTEM_KEYS_11 if c["schemaVersion"] == "1.1" else SYSTEM_KEYS
    if set(c) - TOP_KEYS:
        raise ContextError(f"{path}: unknown key(s) {', '.join(sorted(set(c) - TOP_KEYS))}")
    h = c.get("horizon", DEFAULT_HORIZON)
    if not _year(h) or not 2020 <= h <= 2100:
        raise ContextError(f"{path}: horizon must be a year from 2020 to 2100")
    systems = c.get("systems")
    if not isinstance(systems, list) or not systems:
        raise ContextError(f"{path}: systems must be a non-empty list")
    names = set()
    for i, s in enumerate(systems):
        where = f"{path}: systems[{i}]"
        if not isinstance(s, dict):
            raise ContextError(f"{where}: must be an object")
        if set(s) - allowed:
            extra = sorted(set(s) - allowed)
            hint = " (highValueAsset needs schemaVersion 1.1)" if "highValueAsset" in extra else ""
            raise ContextError(f"{where}: unknown key(s) {', '.join(extra)}{hint}")
        if "highValueAsset" in s and not isinstance(s["highValueAsset"], bool):
            raise ContextError(f"{where}: highValueAsset must be true or false")
        name = s.get("name")
        if not isinstance(name, str) or not name.strip() or name.strip().lower() in names:
            raise ContextError(f"{where}: name must be a unique non-empty string")
        names.add(name.strip().lower())
        if "owner" in s and (not isinstance(s["owner"], str) or not s["owner"].strip()):
            raise ContextError(f"{where}: owner must be a non-empty string")
        if s.get("impact") not in IMPACT:
            raise ContextError(f"{where}: impact must be one of {', '.join(IMPACT)} (FIPS 199)")
        for k in ("dataLifetimeYears", "migrationYears"):
            if k in s and (not _year(s[k]) or not 0 <= s[k] <= 100):
                raise ContextError(f"{where}: {k} must be a whole number of years (0 to 100)")
        eps = s.get("endpoints")
        if not isinstance(eps, list) or not eps or any(not isinstance(e, str) or not e.strip() for e in eps):
            raise ContextError(f"{where}: endpoints must be a non-empty list of patterns")
        for e in eps:
            _pattern(e, where)
    return c


def _port(p, where, pattern):
    if p in (None, ""):
        return None
    if not p.isdigit() or not 0 < int(p) < 65536:
        raise ContextError(f"{where}: bad port in endpoint pattern {pattern!r}")
    return str(int(p))


def _pattern(p, where="pattern"):
    """('net', network, port-or-None) | ('host', glob, port-or-None)."""
    raw, p = p, p.strip().lower().rstrip(".")
    if p.startswith("["):                                     # [IPv6 address or network]:port
        inner, close, rest = p[1:].partition("]")
        if not close or (rest and not rest.startswith(":")):
            raise ContextError(f"{where}: bad endpoint pattern {raw!r}")
        try:
            return ("net", ipaddress.ip_network(inner, strict=False), _port(rest[1:], where, raw))
        except ValueError:
            raise ContextError(f"{where}: bad endpoint pattern {raw!r}")
    try:
        return ("net", ipaddress.ip_network(p, strict=False), None)    # address, network or bare IPv6
    except ValueError:
        pass
    if p.count(":") == 1:
        head, port = p.split(":")
        try:
            return ("net", ipaddress.ip_network(head, strict=False), _port(port, where, raw))   # IPv4 net:port
        except ValueError:
            pass
        host, port = head, _port(port, where, raw)
    elif ":" in p:
        raise ContextError(f"{where}: bad endpoint pattern {raw!r} (an IPv6 network with a port needs brackets)")
    else:
        host, port = p, None
    if not host or not re.fullmatch(r"[a-z0-9*?.\-_]+", host):
        raise ContextError(f"{where}: bad endpoint pattern {raw!r}")
    return ("host", host, port)


def _split(ep):
    """endpoint key (wave.endpoint_key form) -> (host, port)."""
    if ep.startswith("["):
        addr, _, port = ep[1:].partition("]")
        return addr, port.lstrip(":") or "443"
    host, _, port = ep.partition(":")
    return host, port or "443"


def matches(pattern, ep):
    host, port = _split(ep)
    kind, target, want_port = _pattern(pattern)
    if want_port is not None and want_port != port:
        return False
    if kind == "net":
        try:
            return ipaddress.ip_address(host) in target
        except ValueError:
            return False
    return fnmatch.fnmatchcase(host.rstrip("."), target)


def system_horizon(s, ctx_doc):
    """(horizon year, source) for one system: the file's horizon if set, else 2030 for high impact or a
    high-value asset, else 2035."""
    if "horizon" in ctx_doc:
        return ctx_doc["horizon"], "context file"
    if s.get("impact") == "high" or s.get("highValueAsset") is True:
        return HIGH_IMPACT_HORIZON, HIGH_IMPACT_SOURCE
    return DEFAULT_HORIZON, None


def combine(systems, ctx_doc=None):
    """Most demanding values over the systems matching one endpoint, and where each came from."""
    if not systems:
        return None
    imp = max(systems, key=lambda s: IMPACT[s["impact"]])
    life = [s for s in systems if "dataLifetimeYears" in s]
    mig = [s for s in systems if "migrationYears" in s]
    longest = max(life, key=lambda s: s["dataLifetimeYears"]) if life else None
    slowest = max(mig, key=lambda s: s["migrationYears"]) if mig else None
    return {"systems": [s["name"] for s in systems],
            "owners": sorted({s["owner"] for s in systems if s.get("owner")}),
            "impact": imp["impact"],
            "dataLifetimeYears": longest["dataLifetimeYears"] if longest else None,
            "migrationYears": slowest["migrationYears"] if slowest else None,
            "_from": {"impact": imp["name"], "life": longest["name"] if longest else None,
                      "migration": slowest["name"] if slowest else None},
            "horizon": min(system_horizon(s, ctx_doc or {})[0] for s in systems),
            "_per": [(s["name"], s.get("dataLifetimeYears"), s.get("migrationYears"),
                      system_horizon(s, ctx_doc or {})[0]) for s in systems],
            "_impact": {s["name"]: s["impact"] for s in systems}}


def _mosca_one(life, mig, scan_year, horizon, name=None):
    """(urgency, note, understated, reach year) for one system's values."""
    tag = f" ({name})" if name else ""
    if life is None:
        return "not assessed", f"no data lifetime given{tag}", False, -1
    if life == 0:
        return "no", f"data lifetime 0{tag}: nothing recorded now needs to stay confidential", False, scan_year
    if mig is None:
        if scan_year + life > horizon:
            return "yes", (f"{scan_year} + {life} years of confidentiality{tag} = {scan_year + life}, past the "
                           f"{horizon} horizon even before migration time (not given)"), False, scan_year + life
        return "no", (f"migration time not given{tag}; {scan_year} + {life} = {scan_year + life}, within the "
                      f"{horizon} horizon on lifetime alone (urgency may be understated)"), True, scan_year + life
    reach = scan_year + life + mig
    if reach > horizon:
        return "yes", f"{scan_year} + {life} + {mig} years migration{tag} = {reach}, past the {horizon} horizon", \
            False, reach
    return "no", f"{scan_year} + {life} + {mig}{tag} = {reach}, within the {horizon} horizon", False, reach


def mosca(ctx, scan_year, horizon):
    """(urgency, note) for an exposed endpoint: each matched system is evaluated with its own values and the
    most urgent result is reported, so no system borrows another's migration time. 'yes' | 'no' |
    'not assessed'."""
    return mosca_detail(ctx, scan_year, horizon)[:2]


def mosca_detail(ctx, scan_year, horizon):
    """(urgency, note, deciding system names, per-system rows). Each row has the system's own values, horizon and
    result, so the endpoint's urgency can be reproduced from one system's numbers (1.7.0)."""
    per = ctx.get("_per") or [(ctx.get("_from", {}).get("life"), ctx["dataLifetimeYears"], ctx["migrationYears"])]
    # each system is judged against its own horizon (1.7.0: 2030 for high impact); `horizon` is the fallback
    hz = [e[3] if len(e) > 3 else horizon for e in per]
    results = [_mosca_one(e[1], e[2], scan_year, h, e[0] if len(per) > 1 else None) for e, h in zip(per, hz)]
    rows = [{"name": e[0], "impact": (ctx.get("_impact") or {}).get(e[0]), "dataLifetimeYears": e[1],
             "migrationYears": e[2], "horizon": h, "urgent": r[0], "urgency": r[1]}
            for e, h, r in zip(per, hz, results)]
    named = list(zip(per, results))
    yes = [(e, r) for e, r in named if r[0] == "yes"]
    if yes:
        e, r = max(yes, key=lambda x: x[1][3])
        return "yes", r[1], [e[0]], rows
    # "no" is claimed only when every matched system was assessed; the row shows the system closest to the
    # horizon, plus every system whose urgency may be understated
    unknown = [(e, r) for e, r in named if r[0] == "not assessed"]
    if unknown:
        return "not assessed", "; ".join(r[1] for _, r in unknown), [e[0] for e, _ in unknown], rows
    be, best = max(named, key=lambda x: x[1][3])
    under = [r for _, r in named if r[2] and r is not best]
    return "no", "; ".join([best[1]] + [r[1] for r in under]), [be[0]], rows


def exposure(scan, ep):
    """('exposed' | 'not exposed' | 'undetermined', reasons)."""
    iface = scan.interface(ep)
    p = {x.get("name"): x.get("value") for x in (iface or {}).get("properties", []) or [] if isinstance(x, dict)}
    seen, info = scan.channels(ep)
    reasons = []
    kex = [str(x.get("value")) for x in (iface or {}).get("properties", []) or []
           if isinstance(x, dict) and x.get("name") == "pkic:profile:keyExchange"]
    kex_state = []
    for k in kex:
        v = cnsa.classify(k)
        if v.get("canonical") is None and k.upper().startswith("FFDHE-"):   # registry name of an RFC 7919 group
            v = cnsa.classify(k.split("-", 1)[1])
        kex_state.append(None if v.get("canonical") is None else bool(v.get("quantum_vulnerable")))
        if v.get("quantum_vulnerable"):
            reasons.append(f"negotiates {k}")
    # the ruleset's own verdicts on the negotiated session (e.g. a TLS 1.2 DHE suite with no group recorded)
    if iface:
        refs = set(scan.deps.get(iface["bom-ref"], [])) | {iface["bom-ref"]}
        vuln = sorted({f["name"] for r in refs for f in scan.by_ref.get(r, [])
                       if f["lane"] == "key-establishment" and f.get("quantumVulnerable")})
        if not any(r.startswith("negotiates ") for r in reasons):    # only if the session gave no reason yet
            reasons += [f"negotiates {n}" for n in vuln]
    version = str(p.get("pkic:profile:protocolVersion") or "")
    named = version if version.startswith(("TLS", "SSL")) else f"TLSv{version}"
    if version and named in OLD_TLS:
        reasons.append(f"negotiated {named} (no ML-KEM key exchange)")
    if p.get("fedlin:kex_partial_evidence"):
        reasons.append("negotiated a classical group with a FIPS-mode client")
    g = info.get("groups") or {}
    classical_groups = [x for x in g.get("accepted", []) if cnsa.classify(x).get("quantum_vulnerable")]
    if classical_groups:
        reasons.append("accepts classical group(s) " + ",".join(classical_groups))
    if p.get("fedlin:enumeration") == "complete":
        old = [v for v in str(p.get("fedlin:acceptedProtocolVersions", "")).split(",") if v in OLD_TLS]
        if old:
            reasons.append("accepts " + ",".join(old) + " (no ML-KEM key exchange)")
    if p.get("fedlin:classicalOnlyOffer") == "accepted":
        reasons.append("accepted a classical-only client")
    if reasons:
        return "exposed", reasons
    pq_negotiated = bool(kex_state) and all(s is False for s in kex_state)
    classical_checked = info.get("configuration") and p.get("fedlin:classicalOnlyOffer") == "rejected"
    if pq_negotiated and classical_checked:
        return "not exposed", ["ML-KEM negotiated; no classical key exchange accepted in the enumeration or "
                                "the classical-only probe"]
    if not kex:
        return "undetermined", ["key exchange not observed"]
    if any(s is None for s in kex_state):
        return "undetermined", ["key exchange not classified: " + ", ".join(kex)]
    return "undetermined", ["ML-KEM negotiated, but whether classical key exchange is accepted was not fully "
                            "checked (enumeration or classical-only probe incomplete)"]


def _endpoint_sets(scan):
    """(ranked endpoints, {endpoint: reason} seen in the CBOM but not rankable)."""
    ours, others = set(), {}
    for c in scan.comps:
        p = {x.get("name"): x.get("value") for x in c.get("properties", []) or [] if isinstance(x, dict)}
        v = str(p.get("pkic:profile:endpointRole:server", ""))
        ep = wavemod.endpoint_key(v[len("endpoint:"):]) if v.startswith("endpoint:") else (
            wavemod.endpoint_key(p.get("fedlin:host") or c.get("name") or "")
            if (c.get("cryptoProperties") or {}).get("assetType") == "certificate" else None)
        if not ep:
            continue
        if scan._ours(c):
            ours.add(ep)
        elif any(s in wavemod.FRESH for s in evmod.sources_of(c)):
            others.setdefault(ep, "observed by another scan run (merged)")
    return sorted(ours), {k: v for k, v in sorted(others.items()) if k not in ours}


def rank(context_path, cbom_path, profile="civilian", redact=()):
    ctx_doc = load_context(context_path, redact)
    horizon = ctx_doc.get("horizon", DEFAULT_HORIZON)
    source = HORIZON_SOURCE.get(profile, HORIZON_SOURCE["civilian"]) if "horizon" not in ctx_doc else "context file"
    import policy as _policy
    try:
        raw = _policy.load_json(cbom_path)
    except _policy.InputError as e:
        raise ContextError(str(e))
    marked = any(isinstance(x, dict) and x.get("name") == "fedlin:observedIn"
                 for c in (raw.get("components") or []) if isinstance(c, dict) for x in c.get("properties", []) or [])
    # one rule: a CBOM with run markers ranks only its own scan run; one from before markers (toolkit 1.1)
    # ranks its toolkit handshake records
    scan = wavemod.Scan(cbom_path, profile, baseline=not marked)
    try:
        scan_year = int(str(scan.timestamp)[:4])
    except ValueError:
        raise ContextError(f"{cbom_path}: metadata.timestamp is needed for the urgency flag")
    eps, not_ranked = _endpoint_sets(scan)
    rows, unmatched, used = [], [], set()
    for ep in eps:
        hit = [s for s in ctx_doc["systems"] if any(matches(p, ep) for p in s["endpoints"])]
        used |= {s["name"] for s in hit}
        findings = [f for f in scan.findings_at(ep) if f["priority"] in SEVERITY]
        worst = max((SEVERITY[f["priority"]] for f in findings), default=0)
        worst_name = next((k for k, v in SEVERITY.items() if v == worst), None)
        state, why = exposure(scan, ep)
        ctx = combine(hit, ctx_doc)
        if not ctx:
            unmatched.append({"endpoint": ep, "worstPriority": worst_name, "exposure": state, "_w": worst})
            continue
        per_system, decided = None, []
        if state == "exposed":
            urgent, note, decided, per_system = mosca_detail(ctx, scan_year, horizon)
        else:
            urgent, note = ("not assessed" if state == "undetermined" else "no"), "; ".join(why)
        row = {k: v for k, v in ctx.items() if not k.startswith("_")}
        row.update(endpoint=ep, score=IMPACT[ctx["impact"]] * worst, worstPriority=worst_name,
                   findings=len(findings), exposure=state, exposureReasons=why if state == "exposed" else [],
                   urgent=urgent, urgency=note, _w=worst,
                   # combined fields above are maximums across the matched systems (horizon: the earliest);
                   # urgency is decided per system, shown here (1.7.0)
                   perSystem=per_system or [{"name": s, "impact": ctx["_impact"][s],
                                             "dataLifetimeYears": e[1], "migrationYears": e[2], "horizon": e[3]}
                                            for s, e in ((e[0], e) for e in ctx["_per"])],
                   urgencyDecidedBy=decided)
        rows.append(row)
    rows.sort(key=lambda r: (-r["score"], -r["_w"], -IMPACT[r["impact"]], r["urgent"] != "yes", r["endpoint"]))
    unmatched.sort(key=lambda u: (-u["_w"], u["endpoint"]))
    for r in rows + unmatched:
        r.pop("_w", None)
    with_life = {s["name"] for s in ctx_doc["systems"] if "dataLifetimeYears" in s}
    early = sorted(s["name"] for s in ctx_doc["systems"] if "horizon" not in ctx_doc
                   and system_horizon(s, ctx_doc)[0] == HIGH_IMPACT_HORIZON)
    return {
        "resultFormat": RESULT, "resultFormatVersion": RESULT_VERSION, "profile": profile,
        "horizon": horizon, "horizonSource": source, "scanYear": scan_year,
        "horizonBeforeScan": min([horizon] + ([HIGH_IMPACT_HORIZON] if early else [])) < scan_year,
        "highImpactHorizon": None if "horizon" in ctx_doc else HIGH_IMPACT_HORIZON,
        "highImpactHorizonSource": None if "horizon" in ctx_doc else HIGH_IMPACT_SOURCE,
        "systemsOnHighImpactHorizon": early,
        "endpoints": rows, "noContext": unmatched,
        "notRanked": [{"endpoint": k, "reason": v} for k, v in not_ranked.items()],
        "unusedSystems": sorted(s["name"] for s in ctx_doc["systems"] if s["name"] not in used),
        "missingMigrationTime": sorted(n for n in with_life if n in used and not any(
            "migrationYears" in s for s in ctx_doc["systems"] if s["name"] == n)),
        "missingDataLifetime": sorted(s["name"] for s in ctx_doc["systems"]
                                      if s["name"] in used and "dataLifetimeYears" not in s),
    }


def _cell(v):
    """Context-file and CBOM strings made inert in Markdown (GHSA-gmv4-8882-x388), as wave.md_text."""
    return wavemod.md_text(v)


def markdown(att):
    L = ["## Attention order (business context)", ""]
    L.append("Endpoints ranked by FIPS 199 impact x the severity of their worst finding (ties: worse finding first, "
             "then higher impact), with owners. Verdicts and priorities are unchanged. **Urgent** applies to "
             "endpoints exposed to harvest-now-decrypt-later recording (a quantum-vulnerable key exchange "
             "negotiated, or classical key exchange accepted from clients without ML-KEM). It is Mosca's "
             f"inequality with a planning horizon standing in for the time to a quantum computer: the scan year "
             f"({att['scanYear']}) plus the data's confidentiality lifetime plus the migration time reaches past "
             f"the system's horizon: {att['horizon']} ({att['horizonSource']})"
             + (f", or {att['highImpactHorizon']} for a system of high impact or marked a high-value asset "
                f"({att['highImpactHorizonSource']})" if att.get("highImpactHorizon") else "")
             + ". It means the data must stay confidential beyond the "
             "date policy retires these algorithms, not that it will be decrypted then; the horizon is a policy "
             "date, not a forecast. Exposure here includes classical key exchange the server merely accepts, so "
             "it can exceed the harvest-now-decrypt-later count under Top exposures, which covers negotiated "
             "sessions and stored material.")
    if att.get("horizonBeforeScan"):
        L += ["", f"Note: the horizon ({att['horizon']}) is before the scan year, so every exposed endpoint is urgent."]
    L.append("")
    if att["endpoints"]:
        L += ["| # | Endpoint | Systems | Owner | Impact | Worst finding | Exposure | Urgent | Why |",
              "|---|---|---|---|---|---|---|---|---|"]
        for i, r in enumerate(att["endpoints"], 1):
            exp = r["exposure"] + (": " + "; ".join(r["exposureReasons"]) if r["exposureReasons"] else "")
            L.append("| " + " | ".join(_cell(x) for x in (
                i, r["endpoint"], ", ".join(r["systems"]), ", ".join(r["owners"]) or "-", r["impact"],
                r["worstPriority"] or "none", exp, r["urgent"], r["urgency"])) + " |")
    elif not att["noContext"] and not att["notRanked"]:
        L.append("This scan has no endpoint observed by a handshake with recorded evidence (for example a code or "
                 "configuration scan, or a CBOM from before toolkit 1.1), so nothing could be ranked.")
    else:
        L.append("No scanned endpoint matched a system in the context file, so nothing could be ranked.")
    c = _cell
    if att["missingDataLifetime"]:
        L += ["", "No data lifetime given for: " + ", ".join(c(x) for x in att["missingDataLifetime"])
              + ". Their urgency is not assessed."]
    if att["missingMigrationTime"]:
        L += ["", "No migration time given for: " + ", ".join(c(x) for x in att["missingMigrationTime"])
              + ". Their urgency uses the data lifetime alone and may be understated."]
    if att["noContext"]:
        L += ["", "No context (no system pattern matches): "
              + ", ".join(f"{c(u['endpoint'])} ({c(u['worstPriority'] or 'no findings')})" for u in att["noContext"])
              + "."]
    if att["unusedSystems"] and (att["endpoints"] or att["noContext"]):
        L += ["", "Systems with no scanned endpoint (check their patterns): "
              + ", ".join(c(x) for x in att["unusedSystems"]) + "."]
    if att["notRanked"]:
        L += ["", "Not ranked: " + ", ".join(f"{c(n['endpoint'])} ({c(n['reason'])})" for n in att["notRanked"]) + "."]
    L.append("")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("rank", help="attention order and urgency for a CBOM")
    r.add_argument("--context", required=True)
    r.add_argument("--cbom", required=True)
    r.add_argument("--profile", choices=["civilian", "nss"], default="civilian")
    r.add_argument("--json", default="", help="also write the ranking as JSON (fedlin.pqc-attention 1.0)")
    a = ap.parse_args(argv)
    try:
        att = rank(a.context, a.cbom, a.profile)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as e:
        sys.stderr.write(f"[error] {e}\n")
        return 2
    if a.json:
        with open(a.json, "w") as f:
            json.dump(att, f, indent=2)
    print(markdown(att))
    return 0


if __name__ == "__main__":
    sys.exit(main())
