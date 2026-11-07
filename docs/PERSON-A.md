# Instructions — Person A (backend / attack infra)

You own: `catrust/pki.py`, `catrust/server.py`, `catrust/probes.py` (bodies),
`catrust/stores/{system,requests_store,curl_store,firefox,chrome}.py` (bodies),
`catrust/manager.py` (bodies), `catrust/cli.py` (command bodies),
`scenarios/emudhra.yaml` (runtime fields), `tests/` (beyond test_skeleton.py).

DO NOT touch: `catrust/web.py`, `catrust/webapp/*`, `demo.sh`, `README.md`, `docs/PERSON-B.md` — Person B owns those.
DO NOT change signatures in `stores/base.py`, `probes.py` header, `manager.py` header —
Person B builds against them.

## Build order
1. **PKI + server first** (`pki.py`, `server.py`): root CA → intermediate → leaf for
   `localhost` (SAN: DNS:localhost, IP:127.0.0.1), then revoke the leaf and emit a CRL
   from the intermediate. Use `cryptography`. Server: `ssl.SSLContext(PROTOCOL_TLS_SERVER)`
   with the leaf+intermediate chain, on 127.0.0.1:8443, serving a tiny HTML page.
   Verify manually: `openssl s_client -connect 127.0.0.1:8443` shows the chain.
2. **Probes** (`probes.py` bodies): implement `run_probe` for clients
   `requests` (plain `requests.get`, verify=cafile), `requests-crl` (ssl context with
   `VERIFY_CRL_CHECK_LEAF` + CRL loaded), `curl` (`curl --cacert ...`), `openssl-crl`
   (`openssl s_client -crl_check -CRLfile ...`). Capture success vs verify error.
   Key demo fact: plain requests/curl ACCEPT the revoked cert pre-fix (no revocation
   checking by default); crl variants REJECT it.
3. **Stores**: implement audit/remediate for all five. Sandbox paths come from
   `sandbox_root()`; `setup` populates each sandbox store with the compromised root
   (and, for chrome, a crlset.bin NOT containing the serial yet). Remediate = remove
   the root from the bundle / `certutil -D` (or JSON mirror) / rewrite crlset.bin to
   include the revoked serial. Firefox: prefer real `certutil` if present, else maintain
   `onecrl.json` mirror in the fake profile. Chrome: implement `parse_crlset` for the
   length-prefixed block format.
4. **Manager + CLI**: `audit_all`, `remediate_selected`, `load_scenario`, and the CLI
   commands setup/audit/remediate/probe/serve/demo. `demo` = scripted before/after.
5. **Tests**: pytest covering pki round-trip, audit finds root pre-fix, remediate flips
   audit to clean, probes reject post-fix.

## Definition of done
- `pytest` green; `rootcanal setup && rootcanal serve & rootcanal probe` shows
  requests/curl ACCEPT pre-fix and REJECT after `rootcanal remediate`.
