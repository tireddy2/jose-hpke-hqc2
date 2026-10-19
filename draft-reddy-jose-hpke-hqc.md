---
title: Hamming Quasi-Cyclic (HQC) Algorithms for JOSE HPKE
abbrev: HQC for JOSE HPKE
docname: draft-reddy-jose-hpke-hqc-latest
category: std
ipr: trust200902
submissiontype: IETF
v: 3
area: "Security"
workgroup: "Javascript Object Signing and Encryption"
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

Editor's note: This document is based on the HQC specification of
2025-08-22. Before publication as an RFC, the parameter set names,
key and ciphertext encodings and sizes, shared secret size, and
recipient tests need to be checked against the final NIST HQC standard
and updated as necessary. The normative HQC reference in {{HQC-HPKE}}
also needs to be updated. Remove this note before publication.

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

HQC-1 is deliberately included as a smaller option for deployments
that accept its NIST security category 1 target in exchange for
smaller public keys and encapsulated secrets. Implementations should
generally prefer HQC-3 or HQC-5 when these size constraints do not
apply, as discussed in {{HQC-HPKE}}.

Test vectors for the algorithms defined in this section will be
provided in {{test-vectors}} in a future version of this document.

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

Before using a JWK, an implementation MUST verify that its "alg"
value equals the JWE "alg" value selected for that recipient. Matching
only the KEM is insufficient since the Integrated Encryption and Key
Encryption identifiers are distinct.

The "pub" parameter contains the base64url-encoded output of
SerializePublicKey. The "priv" parameter, for private keys, contains
the base64url-encoded output of SerializePrivateKey. This is the
32-octet seed defined by {{HQC-HPKE}}. Expanded private keys MUST NOT
be placed in "priv".

The KEM MUST be determined from "alg", not from the length of "pub".

When importing a JWK, implementations MUST base64url-decode "pub"
and, if present, "priv", and apply the corresponding
DeserializePublicKey and DeserializePrivateKey procedures and input
validation requirements of {{HQC-HPKE}} for the selected KEM. When
both "pub" and "priv" are imported, implementations MUST reconstruct
the public key from the private seed according to {{HQC-HPKE}} for
that KEM and verify that it matches the imported public key. A
mismatch MUST cause the import to fail.

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

The security category targeted by a KEM does not by itself determine
the security of the complete JWE. Message security also depends on
the HPKE KDF and AEAD, any PSK, and, in Key Encryption mode, the
content encryption algorithm selected by the JWE "enc" parameter.
In Integrated Encryption, AES-256-GCM protects the content directly.
In Key Encryption, HPKE's AES-256-GCM protects the CEK; it does not
require the content encryption algorithm to be AES-256-GCM or raise
that algorithm's security strength.

The PQ/T hybrid algorithms are intended to remain secure if either
HQC or the elliptic-curve component remains secure. The HQC-only
algorithms rely on HQC alone.

The traditional component provides protection against classical
attacks if HQC is compromised. Resistance to cryptographically
relevant quantum computers still depends on the HQC component,
together with the security of the symmetric primitives.

The PQ/T hybrid algorithms are RECOMMENDED, following Section 13.3.1
of {{RFC9958}}.

When Key Encryption is used with multiple recipients, all recipients
MUST use a quantum-resistant key management algorithm, as required by
{{JOSE-PQ}}.

Encrypting the same CEK independently for an HQC recipient and an
ML-KEM recipient does not create a hybrid KEM. Recovery of the CEK
through either recipient is sufficient to decrypt the content.

Implementations SHOULD enforce limits on the total encoded JWE size,
the number of recipients, memory allocation, and aggregate
cryptographic work. Size limits need to account for base64url
encoding and, when "ek" is in the protected header, the additional
encoding of that header. In Key Encryption, each HQC recipient adds
an encapsulated secret and an encrypted CEK. Implementations SHOULD
reject messages exceeding applicable limits before allocating large
buffers or starting decapsulation.

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

# Test Vectors {#test-vectors}

Test vectors for the algorithms defined in this document will be
provided in this appendix in a future version.

# Acknowledgments
{:numbered="false"}

TBD.
