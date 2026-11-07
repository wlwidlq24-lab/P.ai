"""Command-line entry point.  `uv run ragsec <command>`  or  `uv run python -m ragsec.cli <command>`."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from .config import LLMBackend, get_settings
from .dataset_gen import generate
from .errors import RagSecError
from .experiments import ingest_dataset, load_dataset, resolve_dataset_dir
from .logstore import read_jsonl
from .metrics import aggregate, write_outputs
from .schemas import ExperimentManifest
from .services import build_services


def _log(level: str) -> None:
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")




def cmd_gen_dataset(args) -> int:
    s = get_settings()
    out = resolve_out(s.dataset_root / args.out)
    manifest = generate(out, seed=args.seed, n_subjects=args.subjects, dataset_version=args.version)
    print(json.dumps({"out": str(out), "documents": manifest.n_documents, "cases": manifest.n_cases,
                      "splits": manifest.split_counts, "content_hash": manifest.content_hash[:16]}, indent=2))
    return 0


def resolve_out(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def cmd_doctor(args) -> int:
    """Administrative diagnostics: uses the ADMIN client (separate from the runtime inference client)."""
    from .hardware import hardware_snapshot, package_versions
    s = get_settings()
    svc = build_services(s)

    async def run():
        hw = hardware_snapshot()
        found = await svc.probe_models_admin()  # admin diagnostics only
        version = svc.ollama_version()
        required = [*s.allowed_target_models, s.embedding_model, s.guard_model]
        missing = [m for m in required if m not in found] if (s.llm_backend == LLMBackend.OLLAMA and version) else []
        vram = (await svc.vram_snapshot_admin()).model_dump() if s.llm_backend == LLMBackend.OLLAMA else None
        try:
            pol = svc.policies().versions
        except RagSecError as e:
            pol = {"error": e.message}
        await svc.aclose()
        print(json.dumps({"backend": s.llm_backend.value, "ollama_url": s.ollama_url,
                          "ollama_version": version or "UNREACHABLE", "vram_profile": s.vram_profile.value,
                          "hardware": hw, "vram_live": vram, "policy_versions": pol, "missing_models": missing,
                          "model_digests": {k: v.digest for k, v in
                                            ((n, found[n]) for n in required if n in found)},
                          "packages": package_versions()}, indent=2, ensure_ascii=False))
        if missing:
            print(f"\nProvision missing models administratively (NOT via the runtime):\n  "
                  + "\n  ".join(f"ollama pull {m}" for m in missing), file=sys.stderr)
        return 0
    return asyncio.run(run())


def cmd_ingest(args) -> int:
    s = get_settings()
    svc = build_services(s)

    async def run():
        ds = load_dataset(resolve_dataset_dir(s, args.dataset))
        res = await ingest_dataset(ds, svc.ingestor, svc.policies(), s, run_llama_guard=not args.no_guard)
        await svc.aclose()
        print(json.dumps({"index_version": res.index_version, "activated": res.activated,
                          "documents": len(res.documents), "skipped_duplicates": res.skipped_duplicates,
                          "validation_errors": res.validation_errors, "embed_ms": round(res.embed_ms, 1)}, indent=2))
        return 1 if res.validation_errors else 0
    return asyncio.run(run())


def cmd_submit(args) -> int:
    """Validate + (optionally) ingest a submission: document files + <id>.meta.json sidecars + optional index.
    A dry run validates only and never modifies the active index."""
    from .ingestion import IngestItem
    from .parsing import parse_document
    from .submission import load_submission
    s = get_settings()
    svc = build_services(s)

    async def run():
        report = load_submission(Path(args.dir), s, policies=svc.policies(), index_name=args.index)
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        if args.dry_run:
            await svc.aclose()
            print(json.dumps({"dry_run": True, "would_ingest": len(report.ok_items),
                              "active_index_unchanged": True}, ensure_ascii=False))
            return 0 if report.ok else 2
        if not report.ok and not args.allow_partial:
            await svc.aclose()
            print(json.dumps({"error": "SUBMISSION_INVALID", "hint": "fix the errors above or pass --allow-partial"},
                             ensure_ascii=False), file=sys.stderr)
            return 2
        items = []
        for it in report.ok_items:
            data = await asyncio.to_thread(it.doc_path.read_bytes)
            parsed = await asyncio.to_thread(parse_document, data, it.doc_path.name, max_bytes=s.max_upload_bytes,
                                             max_pages=s.max_pdf_pages, max_chars=s.max_extracted_chars,
                                             min_chars_per_page=s.min_chars_per_page_for_text_pdf)
            items.append(IngestItem(meta=it.meta, parsed=parsed))
        if not items:
            await svc.aclose()
            print(json.dumps({"ingested": 0, "note": "no valid items to ingest"}), file=sys.stderr)
            return 2
        res = await svc.ingestor.ingest(items, svc.policies(), auto_activate=not args.no_activate,
                                        run_llama_guard=not args.no_guard)
        await svc.aclose()
        print(json.dumps({"index_version": res.index_version, "activated": res.activated,
                          "documents": len(res.documents), "skipped_duplicates": res.skipped_duplicates,
                          "validation_errors": res.validation_errors}, ensure_ascii=False, indent=2))
        return 1 if res.validation_errors else 0
    return asyncio.run(run())


def cmd_validate_submission(args) -> int:
    """Standalone, dependency-free structural validation of a submission index CSV."""
    from .submission import validate_submission_index
    errs = validate_submission_index(Path(args.index))
    print(json.dumps({"index": args.index, "ok": not errs, "errors": errs}, ensure_ascii=False, indent=2))
    return 0 if not errs else 2


def cmd_user_add(args) -> int:
    """Provision a per-user API token (multi-user auth). The token is shown ONCE; only its hash is stored."""
    from .auth import PrincipalStore
    s = get_settings()
    store = PrincipalStore.load(s.principals_file)
    try:
        pols = load_active_policies(s)
        if args.user_id and args.user_id not in {u.user_id for u in pols.users.users}:
            print(f"warning: user_id {args.user_id!r} is not in the user directory", file=sys.stderr)
        if args.tenant and args.tenant not in pols.access.tenants:
            print(f"warning: tenant {args.tenant!r} is not in the access policy", file=sys.stderr)
    except Exception:
        pass
    token = store.add(args.principal_id, user_id=args.user_id, tenant_id=args.tenant,
                      roles=args.roles or [], is_admin=args.admin)
    print(json.dumps({"principal_id": args.principal_id, "token": token,
                      "store_path": str(s.principals_file),
                      "note": "save this token now; only its SHA-256 hash is persisted"}, ensure_ascii=False, indent=2))
    return 0


def cmd_user_list(args) -> int:
    from .auth import PrincipalStore
    s = get_settings()
    store = PrincipalStore.load(s.principals_file)
    print(json.dumps({"principals_file": str(s.principals_file), "principals": store.public_list()},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_user_revoke(args) -> int:
    from .auth import PrincipalStore
    s = get_settings()
    store = PrincipalStore.load(s.principals_file)
    ok = store.revoke(args.principal_id)
    print(json.dumps({"principal_id": args.principal_id, "revoked": ok}, ensure_ascii=False))
    return 0 if ok else 2


def load_active_policies(s):
    from .policy import load_active
    return load_active(s.policy_dir)


def cmd_freeze(args) -> int:
    from .pilot import compute_freeze
    s = get_settings()
    m = ExperimentManifest.model_validate(json.loads(Path(args.manifest).read_text(encoding="utf-8")))
    frozen = compute_freeze(s, m)  # raises DatasetError if any selected attack case is unreviewed
    out = Path(args.out) if args.out else Path(args.manifest).with_suffix(".frozen.json")
    out.write_text(json.dumps(frozen, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"frozen": str(out), "experiment_id": frozen["experiment_id"],
                      "dataset_content_hash": frozen["dataset_content_hash"][:16],
                      "n_cases": len(frozen["selected_case_ids"]),
                      "n_attack": len(frozen["selected_attack_case_ids"])}, indent=2))
    return 0


def cmd_verify_freeze(args) -> int:
    from .pilot import verify_freeze
    s = get_settings()
    frozen = json.loads(Path(args.frozen).read_text(encoding="utf-8"))
    drift = verify_freeze(s, frozen)
    if drift:
        print(json.dumps({"ok": False, "drift": drift}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 3
    print(json.dumps({"ok": True, "experiment_id": frozen["experiment_id"]}, indent=2))
    return 0


def cmd_rule_map(args) -> int:
    """Map a Legal disclosure-rule submission to candidate RolePolicy.disclosure_rules + a Korean comparison.
    Writes candidate/report/result to a SEPARATE output dir (labelled unapproved); never touches active policy."""
    from .rulemap import load_submission, map_submission, write_outputs
    sub = load_submission(Path(args.submission))
    result = map_submission(sub)
    out = write_outputs(result, Path(args.out))
    summary = result.policy_mapping_summary()
    blocked = bool(summary.semantic_mismatches or summary.unresolved_rules) or not result.behavior_ok
    print(json.dumps({"submission_id": result.submission_id, "supported_rules": summary.supported_rules,
                      "semantic_mismatches": summary.semantic_mismatches, "unresolved_rules": summary.unresolved_rules,
                      "behavior_ok": result.behavior_ok, "active_policy_unchanged": True,
                      "outputs": {k: str(v) for k, v in out.items()}}, ensure_ascii=False, indent=2))
    return 3 if blocked else 0   # 0 = clean mapping, 3 = needs Legal correction / unresolved, 2 = tool error (main)


def cmd_preflight(args) -> int:
    """Read-only readiness preflight (G1–G6). Never activates an index, writes a freeze, or runs inference.
    Exit: 0 = READY (still NOT an execution authorization), 3 = blocked readiness, 2 = tool failure."""
    from .preflight import run_preflight
    from .readiness import ReadinessStatus
    s = get_settings()
    m = ExperimentManifest.model_validate(json.loads(Path(args.manifest).read_text(encoding="utf-8")))
    rmr = json.loads(Path(args.rule_mapping).read_text(encoding="utf-8")) if args.rule_mapping else None
    approved = json.loads(Path(args.approved_freeze).read_text(encoding="utf-8")) if args.approved_freeze else None
    report = run_preflight(s, m, rule_mapping_result=rmr, approved_freeze=approved)
    print(report.model_dump_json(indent=2))
    return 0 if report.readiness_status == ReadinessStatus.READY else 3


def cmd_run(args) -> int:
    s = get_settings()
    svc = build_services(s)

    async def run():
        raw = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        m = ExperimentManifest.model_validate(raw)
        if args.verify_freeze:  # reject content drift before executing; never silently refresh hashes
            from .pilot import verify_freeze
            frozen = json.loads(Path(args.verify_freeze).read_text(encoding="utf-8"))
            drift = verify_freeze(s, frozen)
            if drift:
                print(json.dumps({"error": "FREEZE_DRIFT", "drift": drift}, ensure_ascii=False), file=sys.stderr)
                await svc.aclose()
                return 4
            if frozen.get("manifest_hash") and __import__("ragsec.experiments", fromlist=["manifest_hash"]).manifest_hash(m) != frozen["manifest_hash"]:
                print(json.dumps({"error": "MANIFEST_MISMATCH"}), file=sys.stderr)
                await svc.aclose()
                return 4
        # provenance snapshot + VRAM are captured by the runner's pre-run admin probe (JobManager._execute)
        job = svc.jobs.submit(m)
        print(f"run_id={job.run_id} total=pending ... (dir: {job.dir})")
        while not (job.task and job.task.done()):
            await asyncio.sleep(1.0)
            print(f"\r  status={job.status} done={job.done}/{job.total} errors={job.errors}", end="", flush=True)
        print(f"\nfinished: status={job.status} error={job.error}")
        mp = job.dir / "metrics.json"
        if mp.exists():
            print(f"metrics: {mp}")
        await svc.aclose()
        return 0 if job.status == "completed" else 2
    return asyncio.run(run())


def cmd_metrics(args) -> int:
    recs, malformed = read_jsonl(Path(args.jsonl))
    if not recs:
        print("no records", file=sys.stderr)
        return 1
    agg = aggregate(recs)
    agg["malformed_log_lines"] = malformed
    jp, cp = write_outputs(agg, Path(args.out))
    print(json.dumps({"records": len(recs), "malformed": malformed, "json": str(jp), "csv": str(cp),
                      "groups": list(agg["groups"].keys())}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ragsec", description="Korean financial RAG IPI testbed")
    p.add_argument("--log", default="INFO")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-dataset", help="generate a synthetic dataset")
    g.add_argument("--out", default="synthetic/v1")
    g.add_argument("--seed", type=int, default=20261027)
    g.add_argument("--subjects", type=int, default=12)
    g.add_argument("--version", default="1.0.0")
    g.set_defaults(func=cmd_gen_dataset)

    d = sub.add_parser("doctor", help="check environment, Ollama and models")
    d.set_defaults(func=cmd_doctor)

    i = sub.add_parser("ingest", help="ingest a dataset into a new active index version")
    i.add_argument("--dataset", default="synthetic/v1")
    i.add_argument("--no-guard", action="store_true", help="skip Llama Guard at ingestion (faster)")
    i.set_defaults(func=cmd_ingest)

    sb = sub.add_parser("submit", help="validate + ingest a submission (files + .meta.json sidecars + optional index)")
    sb.add_argument("dir", help="directory containing document files and <document_id>.meta.json sidecars")
    sb.add_argument("--index", default="submission_index.csv", help="submission index CSV name (within dir)")
    sb.add_argument("--dry-run", action="store_true", help="validate only; never modifies the active index")
    sb.add_argument("--allow-partial", action="store_true", help="ingest the valid subset even if some items failed")
    sb.add_argument("--no-activate", action="store_true", help="stage the new index version but do not activate it")
    sb.add_argument("--no-guard", action="store_true", help="skip Llama Guard at ingestion (faster)")
    sb.set_defaults(func=cmd_submit)

    vs = sub.add_parser("validate-index", help="structurally validate a submission index CSV (no services)")
    vs.add_argument("index", help="path to the submission index CSV")
    vs.set_defaults(func=cmd_validate_submission)

    ua = sub.add_parser("user-add", help="provision a per-user API token (multi-user auth); token shown once")
    ua.add_argument("principal_id")
    ua.add_argument("--user-id", default=None, help="dataset identity this principal may act as")
    ua.add_argument("--tenant", default=None, help="tenant scope (omit for all-tenant admin)")
    ua.add_argument("--roles", nargs="*", default=[], help="roles granted to this principal")
    ua.add_argument("--admin", action="store_true", help="grant administrative capability")
    ua.set_defaults(func=cmd_user_add)

    ul = sub.add_parser("user-list", help="list principals (metadata only; never tokens)")
    ul.set_defaults(func=cmd_user_list)

    ur = sub.add_parser("user-revoke", help="disable a principal's token")
    ur.add_argument("principal_id")
    ur.set_defaults(func=cmd_user_revoke)

    r = sub.add_parser("run", help="run an experiment manifest to completion (foreground)")
    r.add_argument("manifest")
    r.add_argument("--verify-freeze", default=None, help="path to a .frozen.json; reject content drift before running")
    r.set_defaults(func=cmd_run)

    fz = sub.add_parser("freeze", help="freeze a reviewed pilot manifest (records content hashes)")
    fz.add_argument("manifest")
    fz.add_argument("--out", default=None, help="output path (default: <manifest>.frozen.json)")
    fz.set_defaults(func=cmd_freeze)

    vf = sub.add_parser("verify-freeze", help="verify a .frozen.json against current content (exit 3 on drift)")
    vf.add_argument("frozen")
    vf.set_defaults(func=cmd_verify_freeze)

    rm = sub.add_parser("rule-map", help="map a Legal disclosure-rule submission to candidate config + Korean report")
    rm.add_argument("submission", help="path to a rule submission (.json/.yaml; companion to the Markdown template)")
    rm.add_argument("--out", default="var/rule_mapping", help="output dir for candidate/report/result (unapproved)")
    rm.set_defaults(func=cmd_rule_map)

    pf = sub.add_parser("preflight", help="read-only readiness preflight (G1–G6); never runs or freezes")
    pf.add_argument("manifest", help="experiment manifest JSON")
    pf.add_argument("--rule-mapping", default=None, help="rule-map result JSON (for G1)")
    pf.add_argument("--approved-freeze", default=None, help="human-approved .frozen.json baseline (for G6)")
    pf.set_defaults(func=cmd_preflight)

    mt = sub.add_parser("metrics", help="aggregate a requests.jsonl into metrics.json/csv")
    mt.add_argument("jsonl")
    mt.add_argument("--out", default="var/metrics")
    mt.set_defaults(func=cmd_metrics)

    args = p.parse_args(argv)
    _log(args.log)
    try:
        return args.func(args)
    except RagSecError as e:
        print(json.dumps({"error": e.code, "message": e.message, "detail": e.detail}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
