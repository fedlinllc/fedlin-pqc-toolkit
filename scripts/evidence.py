"""How each CBOM record was observed, written as CycloneDX 1.6 component evidence.

A fact about the record, not a verdict: the policy stage never reads it in 1.x, and verdicts do not
change with it. Each source has one fixed technique and confidence (documented in STABILITY.md);
changing a value is a documented change, never a silent one.

Written on cryptographic-asset records to component.evidence.identity (field "name") as one method
per source, plus component.evidence.occurrences for the endpoint it was seen at. Evidence another tool
wrote is restored verbatim after a merge; records nobody described stay without it ("not stated").

Confidence here is a fixed ordinal ranking of how directly the record was observed, not a calibrated
probability. A record shared by several observations (one algorithm used by several endpoints) lists
every method and every location; CycloneDX cannot tie a method to a location.
"""

# source -> (CycloneDX technique, confidence, what it means)
SOURCES = {
    "handshake": ("dynamic-analysis", 1.0,
                  "observed in a handshake with the endpoint, recorded as its session or certificate"),
    "probe": ("dynamic-analysis", 1.0, "found only by enumeration probe handshakes with the endpoint"),
    "configuration": ("other", 0.8,
                      "read from the system's configuration or certificate stores; use not confirmed"),
    "file": ("other", 0.8, "parsed from a file or container image"),
    "dependency": ("manifest-analysis", 0.3,
                   "inferred from a dependency known to provide it; use not confirmed"),
    "assumption": ("other", 0.1, "assumed, not observed"),
}

PREFIX = "fedlin-pqc-toolkit/"   # marks a method this toolkit wrote (method.value starts with it)


def _walk(components):
    for c in components or []:
        if isinstance(c, dict):
            yield c
            yield from _walk(c.get("components"))


def stamp(comp, source, location=None, detail=None, identify=True):
    """Add the source's method to comp (idempotent; several sources may describe one record).

    identify=False records only where it was seen: for a placeholder name (an unparsed key algorithm)
    the toolkit does not know the identity, so it claims no confidence in it."""
    technique, confidence, meaning = SOURCES[source]
    if not identify:
        if location:
            occ = comp.setdefault("evidence", {}).setdefault("occurrences", [])
            if not any(o.get("location") == location for o in occ):
                occ.append({"location": location})
        return comp
    value = f"{PREFIX}{source}: {meaning}" + (f" ({detail})" if detail else "")
    ev = comp.setdefault("evidence", {})
    ids = ev.get("identity")
    if isinstance(ids, dict):            # CycloneDX 1.5 shape: one object
        ids = [ids]
    if not isinstance(ids, list):
        ids = []
    ev["identity"] = ids
    ident = next((i for i in ids if isinstance(i, dict) and i.get("field") == "name"), None)
    if ident is None:
        ident = {"field": "name", "methods": []}
        ids.append(ident)
    methods = ident.setdefault("methods", [])
    if not any(m.get("technique") == technique and m.get("value") == value for m in methods):
        methods.append({"technique": technique, "confidence": confidence, "value": value})
    confs = [m.get("confidence") for m in methods if isinstance(m.get("confidence"), (int, float))]
    if confs:
        ident["confidence"] = max(confs)
    if location:
        occ = ev.setdefault("occurrences", [])
        if not any(o.get("location") == location for o in occ):
            occ.append({"location": location})
    return comp


def normalize(doc):
    """Write evidence.identity in the CycloneDX 1.6 list form (cyclonedx-cli merge emits the deprecated
    single-object form). Returns how many records were rewritten."""
    n = 0
    for c in _walk(doc.get("components")):
        ev = c.get("evidence")
        if isinstance(ev, dict) and isinstance(ev.get("identity"), dict):
            ev["identity"] = [ev["identity"]]
            n += 1
    return n


def has_identity(comp):
    ids = (comp.get("evidence") or {}).get("identity")
    return bool(ids)


def stamp_missing(doc, source, select=None):
    """Stamp crypto assets that carry no identity evidence (optionally only those select() accepts)."""
    n = 0
    for c in _walk(doc.get("components")):
        if c.get("type") != "cryptographic-asset" or has_identity(c):
            continue
        if select and not select(c):
            continue
        stamp(c, source)
        n += 1
    return n


def sources_of(comp):
    """This toolkit's sources on a record, strongest first; otherwise ["name not parsed"] for the toolkit's
    placeholder for an unreadable key algorithm, ["other tool"] or ["not stated"]."""
    ids = (comp.get("evidence") or {}).get("identity")
    if isinstance(ids, dict):
        ids = [ids]
    found, foreign = [], False
    for i in ids or []:
        for m in (i.get("methods") or []) if isinstance(i, dict) else []:
            v = str(m.get("value") or "")
            if v.startswith(PREFIX):
                s = v[len(PREFIX):].split(":", 1)[0]
                if s in SOURCES and s not in found:
                    found.append(s)
            else:
                foreign = True
    if found:
        return sorted(found, key=lambda s: -SOURCES[s][1])
    if foreign:
        return ["other tool"]
    if str(comp.get("name") or "").startswith("unparsed") and (comp.get("evidence") or {}).get("occurrences"):
        return ["name not parsed"]
    return ["not stated"]


def restore(doc, source_paths):
    """Put back each record's evidence exactly as its original input wrote it.

    cyclonedx-cli convert/merge drop occurrence detail (line, offset, symbol, additionalContext) and
    collapse one-element identity lists. A bom-ref found in several inputs with different evidence is
    left as merged. Returns how many records were restored."""
    import json
    orig, clash = {}, set()
    for path in source_paths:
        try:
            with open(path) as f:
                comps = json.load(f).get("components", [])
        except (OSError, ValueError):
            continue
        for c in _walk(comps):
            ref, ev = c.get("bom-ref"), c.get("evidence")
            if not ref or not isinstance(ev, dict):
                continue
            if ref in orig and orig[ref] != ev:
                clash.add(ref)
            orig.setdefault(ref, ev)
    n = 0
    for c in _walk(doc.get("components")):
        ref = c.get("bom-ref")
        if ref in orig and ref not in clash:
            c["evidence"] = json.loads(json.dumps(orig[ref]))
            n += 1
    return n


def summarize(doc, skip=None):
    """Crypto assets by their strongest source: {source: count}. skip(c) excludes records."""
    out = {}
    for c in _walk(doc.get("components")):
        if c.get("type") != "cryptographic-asset" or (skip and skip(c)):
            continue
        s = sources_of(c)[0]
        out[s] = out.get(s, 0) + 1
    return dict(sorted(out.items()))
