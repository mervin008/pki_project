# Cryptographic posture

What your cryptography is made of, and what it is costing you now.

One distinction governs this whole area, and most reporting on the subject has
it backwards:

> A classical **signature** is a problem in the 2030s.
> A classical **key exchange** is a problem this afternoon.

Nobody forges a handshake that already happened. An RSA-signed certificate
expiring in ninety days is not a quantum risk — it will be replaced many times
before a relevant quantum computer exists. But traffic protected by a classical
key exchange can be **recorded today and decrypted whenever that machine
arrives**, and the fix for that is already shipping in every current browser.

So the interesting data here is about *handshakes*, not certificates. An
inventory can tell you what your certificates are signed with. Only a real
connection to a real server can tell you what it negotiates.

- [Verdicts](#verdicts)
- [Endpoints](#endpoints)
- [CBOM export](#cbom-export)
- [What is deliberately not here](#what-is-deliberately-not-here)

---

## Verdicts

```bash
GET /api/v1/posture
GET /api/v1/posture/endpoints
```

| Verdict | Means | Do |
|:---|:---|:---|
| `EXPOSED` | Traffic here is protected by a key exchange a quantum computer breaks retroactively | This is the one that costs something today |
| `CLASSICAL` | The ordinary state of almost every certificate in the world | A plan, not an incident |
| `HYBRID` | The key exchange is already protected, whatever the certificate is signed with | Nothing |
| `READY` | Post-quantum throughout | Nothing |
| `WEAK` | SHA-1, RSA-1024 — a problem with nothing to do with quantum computing | Fix now |

`WEAK` is separate on purpose. A certificate signed with SHA-1 is a problem
today, for reasons that have nothing to do with 2035, and folding it into a
post-quantum score would bury it.

Requirements are mapped to **CNSA 2.0**: ML-KEM-1024, ML-DSA-87, AES-256,
SHA-384 or SHA-512, and LMS/XMSS for firmware signing. The timeline is
deliberately not encoded — it could not be confirmed from an authoritative
source at the time this was written, and a date wrong by two years in a
compliance report is worse than no date.

---

## Endpoints

The posture assessor sweeps every 15 minutes, and the scanner records what each
handshake actually negotiated:

| Column | |
|:---|:---|
| `tls_version` | What was agreed |
| `group` | The key exchange group — `X25519MLKEM768`, `X25519`, `P-256` |
| `hybrid` | Whether that group is post-quantum hybrid |
| `offered_hybrid` | **Whether CertPilot offered one** |

That last column is the load-bearing one and it looks like the least important.

"This endpoint did not negotiate a post-quantum group" is a finding about the
*server* only if CertPilot offered one. If it did not, the same row is a finding
about CertPilot. Go enables `X25519MLKEM768` by default and that default could
change in a release, so what was offered is recorded per scan rather than
assumed.

The sentence this produces is one no other open-source tool currently gives you:

```
142 of your endpoints do not negotiate X25519MLKEM768.
```

---

## CBOM export

```bash
GET /api/v1/posture/cbom
```

CycloneDX 1.6, validated against the published schema. The point of a
cryptographic bill of materials is that something other than CertPilot reads
it, so it conforms rather than approximating.

Components are `type: "cryptographic-asset"` with an `assetType` of
`algorithm`, `certificate`, `protocol` or `related-crypto-material`, and
`nistQuantumSecurityLevel` as an integer 0–6.

One detail worth knowing, because getting it wrong produces a plausible and
useless document: **the parameter goes in, not just the family name.** "ECDSA"
on its own says nothing about strength — P-256 and P-521 are the same word and
different answers. Security levels are looked up by the displayed name
including its parameter.

---

## What is deliberately not here

**Post-quantum issuance.** Not "not yet built" — not currently possible for
public TLS. The CA/Browser Forum has not updated the Baseline Requirements, and
in February 2026 Google stated Chrome has no near-term plan to accept
post-quantum algorithms in traditional X.509 certificates in its root store,
pursuing [Merkle Tree Certificates](https://datatracker.ietf.org/wg/plants/about/)
instead.

Go's own library reflects this: `crypto/mlkem` exists and `tls.X25519MLKEM768`
is a real curve ID, but there is no `crypto/mldsa`, and `crypto/x509` can
neither build nor parse an ML-DSA certificate. Issuance would have to wait for
the standard library regardless of what a CA supports.

Where it *is* possible today is the private-CA gateways — AWS Private CA has
had ML-DSA generally available since November 2025 — and that is where it will
land first.

**A single score.** There is no "your PKI is 72% quantum-ready" number. It would
be comparable across nothing, and it would average the endpoint losing
confidentiality today with the root certificate that expires in 2035.
