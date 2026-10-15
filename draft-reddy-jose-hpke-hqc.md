---
title: Hamming Quasi-Cyclic (HQC) Algorithms for JOSE HPKE
abbrev: HQC for JOSE HPKE
docname: draft-reddy-jose-hpke-hqc-latest
category: std
ipr: trust200902
submissiontype: IETF
v: 3
area: "Security"
workgroup: "JSON Object Signing and Encryption"
keyword:
- HQC
- JOSE
- JWE
- HPKE
- Post-Quantum Cryptography
author:
- fullname: Tirumaleswar Reddy
  organization: Nokia
  city: Bangalore
  region: Karnataka
  country: India
  email: kondtir@gmail.com
- fullname: Hannes Tschofenig
  organization: University of the Bundeswehr Munich
  abbrev: UniBw M.
  city: Neubiberg
  code: '85577'
  country: Germany
  email: hannes.tschofenig@gmx.net
normative:
  RFC7516:
  RFC9964:
  HPKE: I-D.ietf-hpke-hpke
  PQ-HPKE: I-D.ietf-hpke-pq
  HQC-HPKE: I-D.reddy-hpke-hqc
  JOSE-HPKE: I-D.ietf-jose-hpke-encrypt
  JOSE-PQ: I-D.ietf-jose-hpke-pq-pqt
informative:
  RFC7518:
  RFC9794:
  RFC9958:
  COSE-HQC: I-D.reddy-cose-hpke-hqc

--- abstract

This document registers JSON Web Encryption (JWE) algorithms that use
Hybrid Public Key Encryption (HPKE) with Hamming Quasi-Cyclic (HQC)
key encapsulation. It covers HQC alone and PQ/T hybrid HQC KEMs, each
with SHAKE256 key derivation and AES-256-GCM authenticated encryption.
It defines algorithms for Integrated Encryption and Key Encryption and
requests twelve JOSE algorithm registrations.

--- middle

# Introduction

{{JOSE-HPKE}} defines the use of HPKE {{HPKE}} with JWE {{RFC7516}}
in two modes, Integrated Encryption and Key Encryption. {{JOSE-PQ}}
adds algorithms for the ML-KEM and ML-KEM PQ/T hybrid KEMs of
{{PQ-HPKE}}.

This document adds algorithms for the KEMs of {{HQC-HPKE}}: HQC-1,
HQC-3, and HQC-5, and the PQ/T hybrid {{RFC9794}} KEMs HQC3-P256,
HQC3-X25519, and HQC5-P384. Each KEM is combined with the SHAKE256 KDF
of {{PQ-HPKE}} and AES-256-GCM. The approach follows {{JOSE-PQ}}.

This document does not change the JWE processing of {{JOSE-HPKE}}.
{{COSE-HQC}} defines the corresponding COSE algorithms.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The terms Integrated Encryption, Key Encryption, and encapsulated
secret are used as defined in {{JOSE-HPKE}}. The term PQ/T hybrid is
used as defined in {{RFC9794}}.

# Algorithm Identifiers {#algs}

Each algorithm identifies one HPKE KEM, KDF, and AEAD, and one JWE
mode. Implementations MUST NOT substitute another KEM, KDF, or AEAD
under the same algorithm identifier.

For every algorithm, the HPKE KDF is SHAKE256 (0x0011) as defined in
{{PQ-HPKE}}, and the HPKE AEAD is AES-256-GCM (0x0002) as defined in
{{HPKE}}. The HPKE KEM ID is the value assigned to the KEM by
{{HQC-HPKE}}.

SHAKE256 is selected because HQC-KEM uses SHAKE256 internally. This
is the same rationale as {{JOSE-PQ}} for ML-KEM.

The algorithm names are the same as the COSE algorithm names in
{{COSE-HQC}}.

## Integrated Encryption {#integrated}

The algorithms in {{ie-table}} use Integrated Encryption as defined
in Section 5 of {{JOSE-HPKE}}.

| "alg" | HPKE KEM |
|:------|:---------|
| HPKE-HQC-1 | HQC-1 |
| HPKE-HQC-3 | HQC-3 |
| HPKE-HQC-5 | HQC-5 |
| HPKE-HQC3-P256 | HQC3-P256 |
| HPKE-HQC3-X25519 | HQC3-X25519 |
| HPKE-HQC5-P384 | HQC5-P384 |
{: #ie-table title="HQC Integrated Encryption algorithms"}

## Key Encryption {#ke}

The algorithms in {{ke-table}} use Key Encryption as defined in
Section 6 of {{JOSE-HPKE}}.

| "alg" | HPKE KEM |
|:------|:---------|
| HPKE-HQC-1-KE | HQC-1 |
| HPKE-HQC-3-KE | HQC-3 |
| HPKE-HQC-5-KE | HQC-5 |
| HPKE-HQC3-P256-KE | HQC3-P256 |
| HPKE-HQC3-X25519-KE | HQC3-X25519 |
| HPKE-HQC5-P384-KE | HQC5-P384 |
{: #ke-table title="HQC Key Encryption algorithms"}

# JSON Web Key Representation {#jwk}

Keys use the "AKP" key type of {{RFC9964}}, as in {{JOSE-PQ}}. The
"alg" parameter is REQUIRED and MUST identify one algorithm from
{{algs}}.

The "pub" parameter contains the base64url-encoded output of
SerializePublicKey. The "priv" parameter, for private keys, contains
the base64url-encoded output of SerializePrivateKey. This is the
32-octet seed defined by {{HQC-HPKE}}. Expanded private keys MUST NOT
be placed in "priv".

The KEM MUST be determined from "alg", not from the length of "pub".

# Encapsulated Secret Lengths {#lengths}

In Integrated Encryption, the encapsulated secret is carried in the
JWE Encrypted Key. In Key Encryption, it is carried in the "ek"
header parameter. {{len-table}} gives the decoded lengths of "pub"
and of the encapsulated secret. A recipient MUST reject an
encapsulated secret of the wrong length before decapsulation.

| HPKE KEM | "pub" (octets) | Encapsulated secret (octets) |
|:---------|---------------:|-----------------------------:|
| HQC-1 | 2241 | 4433 |
| HQC-3 | 4514 | 8978 |
| HQC-5 | 7237 | 14421 |
| HQC3-P256 | 4579 | 9043 |
| HQC3-X25519 | 4546 | 9010 |
| HQC5-P384 | 7334 | 14518 |
{: #len-table title="Public key and encapsulated secret lengths"}

# Security Considerations

The security considerations of {{HQC-HPKE}}, {{JOSE-HPKE}}, and
{{JOSE-PQ}} apply.

The PQ/T hybrid algorithms are intended to remain secure if either
HQC or the elliptic-curve component remains secure. The HQC-only
algorithms rely on HQC alone.

The PQ/T hybrid algorithms are RECOMMENDED, following Section 13.3.1
of {{RFC9958}}.

When Key Encryption is used with multiple recipients, all recipients
MUST use a quantum-resistant key management algorithm, as required by
{{JOSE-PQ}}.

# IANA Considerations {#iana}

IANA is requested to add the following twelve entries to the "JSON
Web Signature and Encryption Algorithms" registry established by
{{RFC7518}}.

| Algorithm Name | Algorithm Description |
|:---------------|:----------------------|
| HPKE-HQC-1 | Integrated Encryption with HPKE using HQC-1 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
| HPKE-HQC-3 | Integrated Encryption with HPKE using HQC-3 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
| HPKE-HQC-5 | Integrated Encryption with HPKE using HQC-5 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
| HPKE-HQC3-P256 | Integrated Encryption with HPKE using HQC3-P256 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
| HPKE-HQC3-X25519 | Integrated Encryption with HPKE using HQC3-X25519 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
| HPKE-HQC5-P384 | Integrated Encryption with HPKE using HQC5-P384 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
| HPKE-HQC-1-KE | Key Encryption with HPKE using HQC-1 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
| HPKE-HQC-3-KE | Key Encryption with HPKE using HQC-3 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
| HPKE-HQC-5-KE | Key Encryption with HPKE using HQC-5 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
| HPKE-HQC3-P256-KE | Key Encryption with HPKE using HQC3-P256 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
| HPKE-HQC3-X25519-KE | Key Encryption with HPKE using HQC3-X25519 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
| HPKE-HQC5-P384-KE | Key Encryption with HPKE using HQC5-P384 KEM, SHAKE256 KDF, and AES-256-GCM AEAD |
{: #iana-table title="JOSE algorithm registrations"}

The following fields apply to every entry:

* Algorithm Usage Location(s): "alg"
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): {{integrated}} of this document for
  Integrated Encryption entries, {{ke}} of this document for Key
  Encryption entries
* Algorithm Analysis Document(s): {{HQC-HPKE}}

--- back

# Acknowledgments
{:numbered="false"}

TBD.
