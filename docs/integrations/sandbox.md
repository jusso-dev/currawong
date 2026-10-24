# On-premises sandbox detonation

Sandboxing is off by default. Run CAPEv2 on a separate isolated on-premises host with its analysis VMs. Currawong talks HTTP only. CAPEv2 is GPL-3.0; Currawong neither vendors nor links it. Guest OS licences and containment are operator responsibilities. Do not expose analysis APIs or guest networks publicly.

Verified 24 October 2026: [CAPEv2 API examples](https://github.com/kevoreilly/CAPEv2/blob/master/web/templates/apiv2/index.html), [current API implementation and schemas](https://github.com/kevoreilly/CAPEv2/blob/master/web/apiv2/views.py), [web setup](https://capev2.readthedocs.io/en/latest/usage/web.html). The older Cuckoo `/tasks/create/file` response is not the CAPEv2 `/apiv2` contract.

Install CAPE, its hypervisor and guest VM using [upstream installation](https://capev2.readthedocs.io/en/latest/installation/). Start CAPE's scheduler/processing and web services using upstream deployment guidance. On an installed development host, upstream's web command can be restricted to loopback:

```sh
cd /opt/CAPEv2/web
poetry run python3 manage.py runserver_plus 127.0.0.1:8000 --traceback --keep-meta-shutdown
```

This development server is not a production deployment. Use CAPE's maintained service configuration and verified HTTPS/private network access for a gateway on another host. Enable `filecreate`, `taskstatus` and `taskreport` in CAPE's `api.conf`; configure token authentication, a dedicated account and report-download permissions. Store its token in a readable-only-by-service file on the gateway. Configure CAPE's routing so guests cannot reach internal services or send customer data to public analysis services. No generic Docker Compose file can supply CAPE's required isolated guest VMs; this guide does not pretend a web container alone runs detonation.

```toml
[scanner.sandbox]
kind = "cape"
url = "http://127.0.0.1:8000"
token_file = "/etc/currawong/cape-token"
required = true
max_wait_secs = 900
poll_secs = 30
submit = ["executable", "script", "office", "pdf", "archive", "disk_image", "html"]
max_file_size = 20971520
on_timeout = "quarantine"
cache_ttl_secs = 86400
```

- Submit: `POST /apiv2/tasks/create/file/`, multipart field `file`, `Authorization: Token ...`. Expect `error = false` and exactly one `data.task_ids` entry.
- Poll: `GET /apiv2/tasks/status/<id>/`. `data` contains state; only `reported` permits report retrieval. Analysis/processing/reporting failures fail closed, never clean.
- Verdict: `GET /apiv2/tasks/get/report/<id>/json/`. Read `malscore` (0..10) and `signatures[].name`. Currawong's threshold is 5/10, its report score is 0..1. Reports without required fields fail closed.

The parser records attachment disposition in `PartInfo.is_attachment`, including HTML attachments without a filename. Ordinary unnamed HTML message bodies are not detonated. Named HTML parts and archive members are selected. Static HTML-smuggling checks still cover all HTML parts. Executable filename selection supplements true-type flags, including headerless `.com` files.

The sandbox URL is added to residency checks. Every request is checked and pinned, has no environment proxy, and refuses all redirects. Sandbox peers must also resolve to local/private addresses; a public Australian cloud endpoint is refused even if residency allows it. On another host, add its exact hostname and private CIDR to residency. HTTP requests have a 15-second deadline; create replies are capped at 64 KiB, reports/status at 8 MiB.

Tasks/verdicts persist in `spool.dir/sandbox.sqlite3`, keyed by service and SHA-256. First submission defers with `awaiting sandbox`; later spool attempts poll without reuploading. `poll_secs` also sets pending spool retry delay, subject to the scheduler loop cadence. Terminal verdicts/failures expire lazily after `cache_ttl_secs`; pending tasks use original submission age, not retry count. Cache age is bounded; row count has no separate quota. Retain the database across daemon restarts and protect it with the spool's filesystem permissions.

A crash or lost upload response may leave an unknown task reservation. It is not immediately resubmitted. It eventually follows timeout. Unknown submissions do not expire before that deadline, even when the verdict cache TTL is shorter. This avoids repeated detonation but can delay a file whose upload never reached CAPE. A failed required service defers; optional failure adds a note. Invalid reports, attachment read/hash failures and risky files above `max_file_size` fail closed. Malicious results always use the malware quarantine floor. `on_timeout = "deliver"` lets only the sandbox timeout pass; macros, file-type policies, ClamAV and other findings still apply. Existing `max_scan_deferrals` can end retries earlier than sandbox timeout if set too low.

DRAKVUF Sandbox not implemented. Its current upstream [API](https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/drakrun/web/api.py) verifies `POST /api/upload`, `GET /api/status/<task_uid>` and `GET /api/report/<task_uid>`. [Report generation](https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/drakrun/analyzer/postprocessing/plugins/generate_report.py) and [usage documentation](https://drakvuf-sandbox.readthedocs.io/en/stable/usage/basic_usage.html) describe observations/TTPs, not a verified malicious/clean verdict or score contract. Treating successful analysis as clean would be unsafe. `kind = "drakvuf"` therefore fails configuration validation until an explicit verdict adapter can be specified and tested.

No real CAPE/DRAKVUF instance, hypervisor, guest VM or malware was run. All fixtures are generated benign files. See [validation](../VALIDATION.md).
