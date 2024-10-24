%%%
title = "Blind BBS Signatures"
abbrev = "Blind BBS Signatures"
ipr= "trust200902"
area = "Internet"
workgroup = "none"
submissiontype = "IETF"
keyword = [""]

[seriesInfo]
name = "Internet-Draft"
value = "draft-kalos-bbs-blind-signatures-latest"
status = "informational"

[[author]]
initials = "V."
surname = "Kalos"
fullname = "Vasilis Kalos"
#role = "editor"
organization = "MATTR"
  [author.address]
  email = "vasilis.kalos@mattr.global"

[[author]]
initials = "G."
surname = "Bernstein"
fullname = "Greg M. Bernstein"
#role = "editor"
organization = "Grotto Networking"
  [author.address]
  email = "gregb@grotto-networking.com"
%%%

.# Abstract

This document defines an extension to the BBS Signature scheme that supports blind digital signatures, i.e., signatures over messages not known to the Signer.

{mainmatter}

# Introduction

The BBS digital signature scheme, as defined in [@!I-D.irtf-cfrg-bbs-signatures], can be extended to support blind signatures functionality. In a blind signatures setting, the user (called the Prover in the context of the BBS scheme) will request a signature on a list of messages, without revealing those messages to the Signer (who can optionally also include messages of their choosing to the signature).

By allowing the Prover to acquire a valid signature over messages not known to the Signer, blind signatures address some limitations of their plain digital signature counterparts. In the BBS scheme, knowledge of a valid signature allows generation of BBS proofs. As a result, a signature compromise (by an eavesdropper, a phishing attack, a leakage of the Signer's logs etc.,) can lead to impersonation of the Prover by malicious actors (especially in cases involving "long-lived" signatures, as in digital credentials applications etc.,). Using Blind BBS Signatures on the other hand, the Prover can commit to a secret message (for example, a private key) before issuance, guaranteeing that no one will be able to generate a valid proof without knowledge of their secret.

Furthermore, applications like Privacy Pass ([@I-D.ietf-privacypass-protocol]) may require a signature to be "scoped" to a specific audience or session (as to require "fresh" signatures for different sessions etc.,). However, simply sending an audience or session identifier to the Signer (to be included in the signature), will compromise the privacy guarantees that these applications try to enforce. Using blind signing, the Prover will be able to require signatures bound to those values, without having to reveal them to the Signer.

The presented protocol, compared to the scheme defined in [@!I-D.irtf-cfrg-bbs-signatures], introduces an additional communication step between the Prover and the Signer. The Prover will start by constructing a "hiding" commitment to the messages they want to get a signature on (i.e., a commitment which reveals no information about the committed values), together with a proof of correctness of that commitment. They will send the (commitment, proof) pair to the Signer, who, upon receiving the pair, will attempt to verify the commitment's proof of correctness. If successful, they will use it in generating a BBS signature over the messages committed by the Prover, including their own messages if any.

This document, in addition to defining the operation for creating and verifying a commitment, also details a core signature generation operation, different from the one presented in [@!I-D.irtf-cfrg-bbs-signatures], meant to handle the computation of the blind signature. The document will also define a new BBS Interface, which is needed to handle the different inputs, i.e., messages committed by the Prover or chosen by the Signer etc... The signature verification and proof generation core cryptographic operations however, will work as described in [@!I-D.irtf-cfrg-bbs-signatures]. To further facilitate deployment, both the exposed interface as well as the core cryptographic operation of proof verification will be the same as the one detailed in [@!I-D.irtf-cfrg-bbs-signatures].

Below is a basic diagram describing the main entities involved in the scheme.
!---
~~~ ascii-art
 (3) Blind Sign                                          (1) Commit
     +-----                                                +-----
     |    |                                                |    |
     |    |                                                |    |
     |   \ /                                               |   \ /
  +----------+                                          +-----------+
  |          |                                          |           |
  |          |                                          |           |
  |          |<-(2)* Commitment + Proof of Correctness--|           |
  |  Signer  |                                          |   Prover  |
  |          |-------(4)* Send signature + msgs-------->|           |
  |          |                                          |           |
  |          |                                          |           |
  +----------+                                          +-----------+
                                                              |
                                                              |
                                                              |
                                                      (5)* Send proof
                                                              +
                                                       disclosed msgs
                                                              |
                                                              |
                                                             \ /
                                                        +-----------+
                                                        |           |
                                                        |           |
                                                        |           |
                                                        |  Verifier |
                                                        |           |
                                                        |           |
                                                        |           |
                                                        +-----------+
                                                           |   / \
                                                           |    |
                                                           |    |
                                                           +-----
                                                      (6) ProofVerify
~~~
!---
Figure: Basic diagram capturing the main entities involved in using the scheme.

**Note** The protocols implied by the items annotated by an asterisk are out of scope for this specification

## Terminology

Terminology defined by [@!I-D.irtf-cfrg-bbs-signatures] applies to this draft.

Additionally, the following terminology is used throughout this document:

blind\_signature
: The blind digital signature output.

commitment
: A point of G1, representing a Pedersen commitment ([@P91]) constructed over a vector of messages, as described e.g., in [@BG18].

committed\_messages
: A list of messages committed by the Prover to a commitment.

commitment\_proof
: A zero knowledge proof of correctness of a commitment, consisting of a scalar value, a possibly empty set of scalars (of length equal to the number of committed\_messages, see above) and another scalar, in that order.

secret\_prover\_blind
: A random scalar used to blind (i.e., randomize) the commitment constructed by the prover.

signer\_blind
: A random scalar used by the signer to optionally re-blind the received commitment.

## Notation

Notation defined by [@!I-D.irtf-cfrg-bbs-signatures] applies to this draft.

Additionally, the following notation and primitives are used:

list.append(elements)
: Append either a single element or a list of elements to the end of a list, maintaining the same order of the list's elements as well as the appended elements. For example, given `list = [a, b, c]` and `elements = [d, a]`, the result of `list.append(elements)` will be `[a, b, c, d, a]`.

# Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all capitals, as shown here.

# BBS Signature Scheme Operations

This document makes use of various operations defined by the BBS Signature Scheme document [@!I-D.irtf-cfrg-bbs-signatures]. For clarity, whenever an operation will be used defined in [@!I-D.irtf-cfrg-bbs-signatures], it will be prefixed by "BBS." (e.g., "BBS.CoreProofGen" etc.). More specifically, the operations used are the following:

- `BBS.CoreVerify`: Refers to the `CoreVerify` operation defined in [Section 3.6.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-coreverify) of [@!I-D.irtf-cfrg-bbs-signatures].
- `BBS.CoreProofGen`: Refers to the `CoreProofGen` operation defined in [Section 3.6.3](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-coreproofgen) of [@!I-D.irtf-cfrg-bbs-signatures].
- `BBS.create_generators`: Refers to the `create_generators` operation defined in [Section 4.1.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-generators-calculation) of [@!I-D.irtf-cfrg-bbs-signatures].
- `BBS.messages_to_scalars`: Refers to the `messages_to_scalars` operation defined in [Section 4.1.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-messages-to-scalars) of [@!I-D.irtf-cfrg-bbs-signatures].
- `BBS.get_random_scalars`: Refers to the `get_random_scalars` operation defined in [Section 4.2.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-random-scalars) of [@!I-D.irtf-cfrg-bbs-signatures].
- `BBS.hash_to_scalar`: Refers to the `hash_to_scalar` operation defined in [Section 4.2.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-hash-to-scalar) of [@!I-D.irtf-cfrg-bbs-signatures].
- `BBS.calculate_domain`: Refers to the `calculate_domain` operation defined in [Section 4.2.3](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-07.html#domain-calculation) of [@!I-D.irtf-cfrg-bbs-signatures].

# Scheme Definition

## Commitment Operations

### Commitment Computation

This operation is used by the Prover to create a `commitment` to a set of messages (`committed_messages`), that they intend to include in the blind signature. Note that this operation returns both the serialized combination of the commitment and its proof of correctness (`commitment_with_proof`), as well as the random scalar used to blind the commitment (`secret_prover_blind`).

```
(commitment_with_proof, secret_prover_blind) = commit(
                                                   committed_messages,
                                                   api_id)

Inputs:

- committed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied it defaults to the empty
                                 array ("()").
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- (commitment_with_proof, secret_prover_blind), a tuple comprising from
                                                an octet string and a
                                                random scalar in that
                                                order.

Procedure:

1. committed_message_scalars = BBS.messages_to_scalars(
                                             committed_messages, api_id)

2. blind_generators = BBS.create_generators(
                                  length(committed_message_scalars) + 1,
                                  "BLIND_" || api_id)

3. return CoreCommit(committed_message_scalars,
                             blind_generators, api_id)
```

###  Commitment Validation and Deserialization

The following is a helper operation used by the `BlindSign` procedure ((#blind-signature-generation)) to validate an optional commitment. If a `commitment` is not supplied, or if it is the `Identity_G1`, the following operation will return the `Identity_G1` as the "default" commitment point, which will be ignored by all computations during `BlindSign`.

```
commit = deserialize_and_validate_commit(commitment_with_proof,
                                               blind_generators, api_id)

Inputs:

- commitment_with_proof (OPTIONAL), octet string. If it is not supplied
                                    it defaults to the empty octet
                                    string ("").
- blind_generators (OPTIONAL), vector of points of G1. If it is not
                               supplied it defaults to the empty set
                               ("()").
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- commit, a point of G1; or INVALID.

Procedure:

1. if commitment_with_proof is the empty string (""), return Identity_G1

2. com_res = octets_to_commitment_with_proof(commitment_with_proof)
3. if com_res is INVALID, return INVALID

4. (commit, commit_proof) = com_res
5. if length(commit_proof[1]) + 1 != length(blind_generators),
                                                          return INVALID

6. validation_res = CoreCommitVerify(commit, commit_proof,
                                               blind_generators, api_id)
7. if validation_res is INVALID, return INVALID
8. commitment
```

## Blind BBS Signatures Interface

The following section defines a BBS Interface for blind BBS signatures. The identifier of the Interface is defined as `ciphersuite_id || BLIND_H2G_HM2S_`, where `ciphersuite_id` the unique identifier of the BBS ciphersuite used, as is defined in [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]). Each BBS Interface MUST define operations to map the input messages to scalar values and to create the generator set, required by the core operations. The input messages to the defined Interface will be mapped to scalars using the `messages_to_scalars` operation defined in [Section 4.1.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-messages-to-scalars) of [@!I-D.irtf-cfrg-bbs-signatures]. The generators will be created using the `create_generators` operation defined in [Section 4.1.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-generators-calculation) of [@!I-D.irtf-cfrg-bbs-signatures].

Other than the `BlindSign` operation defined in (#blind-signature-generation), which uses the `FinalizeBlindSign` procedure, defined in (#finalize-blind-sign), all other interface operations defined in this section use the core operations defined in [Section 3.6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-core-operations) of [@!I-D.irtf-cfrg-bbs-signatures].

### Blind Signature Generation

This operation returns a BBS blind signature from a secret key (SK), over a `header`, a set of `messages` and optionally a commitment value (see (#terminology)). If supplied, the commitment value must be accompanied by its proof of correctness (`commitment_with_proof`, as outputted by the `Commit` operation defined in (#commitment-computation)).

The `BlindSign` operation makes use of the `FinalizeBlindSign` procedure defined in (#finalize-blind-sign) and the `B_calculate` procedure defined in (#calculate-b-value). The `B_calculate` is defined to return an array of elements, to establish extendability of the scheme by allowing the `B_calculate` operation to return more elements than just the point to be signed.

```
blind_signature = BlindSign(SK, PK, commitment_with_proof, header,
                                                               messages)

Inputs:

- SK (REQUIRED), a secret key in the form outputted by the KeyGen
                 operation.
- PK (REQUIRED), an octet string of the form outputted by SkToPk
                 provided the above SK as input.
- commitment_with_proof (OPTIONAL), an octet string, representing a
                                    serialized commitment and
                                    commitment_proof, as the first
                                    element outputted by the Commit
                                    operation. If not supplied, it
                                    defaults to the empty string ("").
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string ("").
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array ("()").

Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string composed of 15 bytes.
- (octet_point_length, octet_scalar_length), defined by the ciphersuite.

Outputs:

- blind_signature, a blind signature encoded as an octet string; or
                   INVALID.


Deserialization:

1. L = length(messages)

// calculate the number of blind generators used by the commitment,
// if any.
2. M = length(commitment_with_proof)
3. if M != 0, M = M - octet_point_length - octet_scalar_length
4. M = M / octet_scalar_length
5. if M < 0, return INVALID

Procedure:

1.  generators = BBS.create_generators(L + 1, api_id)
2.  blind_generators = BBS.create_generators(M, "BLIND_" || api_id)

3.  commit = deserialize_and_validate_commit(commitment_with_proof,
                                               blind_generators, api_id)
4.  if commit is INVALID, return INVALID

5.  (msg_1, ..., msg_L) = BBS.messages_to_scalars(messages, api_id)

6.  res = B_calculate(generators, commit, messages)
7.  if res is INVALID, return INVALID
8.  (B) = res

9.  blind_sig = FinalizeBlindSign(SK,
                                  PK,
                                  B,
                                  generators,
                                  blind_generators,
                                  header,
                                  api_id)
10. if blind_sig is INVALID, return INVALID
11. return blind_sig
```

### Blind Signature Verification

This operation validates a blind BBS signature (`signature`), given the Signer's public key (`PK`), a header (`header`), a set of, known to the Signer, messages (`messages`) and if used, a set of committed messages (`committed_messages`) and the `secret_prover_blind` as returned by the `Commit` operation ((#commitment-computation)).

This operation makes use of the `CoreVerify` operation as defined in [Section 3.6.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-coreverify) of [@!I-D.irtf-cfrg-bbs-signatures].

```
result = Verify(PK, signature, header, messages, committed_messages,
                                                    secret_prover_blind)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array "()".
- committed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied, it defaults to the empty
                                 array "()".
- secret_prover_blind (OPTIONAL), a scalar value. If not supplied it
                                  defaults to zero "0".


Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string composed of 15 bytes.

Outputs:

- result: either VALID or INVALID

Procedure:

1. message_scalars = BBS.messages_to_scalars(messages, api_id)

2. committed_message_scalars = ()
4. committed_message_scalars.append(secret_prover_blind)
5. committed_message_scalars.append(BBS.messages_to_scalars(
                                            committed_messages, api_id))

6. generators = BBS.create_generators(length(message_scalars) + 1, api_id)
7. blind_generators = BBS.create_generators(length(committed_message_scalars), "BLIND_" || api_id)

8. res = BBS.CoreVerify(
                     PK,
                     signature,
                     generators.append(blind_generators),
                     header,
                     message_scalars.append(committed_message_scalars),
                     api_id)
9. return res
```

### Proof Generation

This operation creates a BBS proof, which is a zero-knowledge, proof-of-knowledge, of a BBS signature, while optionally disclosing any subset of the signed messages. Note that in contrast to the `ProofGen` operation of [@!I-D.irtf-cfrg-bbs-signatures] (see [Section 3.5.3](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-generation-proofgen)), the `ProofGen` operation defined in this section accepts 2 different lists of messages and disclosed indexes, one for the messages known to the Signer (`messages`) and the corresponding disclosed indexes (`disclosed_indexes`) and one for the messages committed by the Prover (`committed_messages`) and the corresponding disclosed indexes (`disclosed_commitment_indexes`).

Furthermore, the operation also expects the `secret_prover_blind` (as returned from the `Commit` operation defined in (#commitment-computation)) value. If the BBS signature is generated using a commitment value, then the `secret_prover_blind` returned by the `Commit` operation used to generate the commitment should be provided to the `ProofGen` operation (otherwise the resulting proof will be invalid).

This operation makes use of the `CoreProofGen` operation as defined in [Section 3.6.3](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-coreproofgen) of [@!I-D.irtf-cfrg-bbs-signatures].

```
proof = BlindProofGen(PK,
                      signature,
                      header,
                      ph,
                      messages,
                      committed_messages,
                      disclosed_indexes,
                      disclosed_commitment_indexes,
                      secret_prover_blind)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array "()".
- committed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied, it defaults to the empty
                                 array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".
- disclosed_commitment_indexes (OPTIONAL), vector of unsigned integers
                                           in ascending order. Indexes
                                           of disclosed committed
                                           messages. If not supplied, it
                                           defaults to the empty array
                                           "()".
- secret_prover_blind (OPTIONAL), a scalar value. If not supplied it
                                  defaults to zero "0".


Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string composed of 15 bytes.

Outputs:

- proof, an octet string; or INVALID.

Deserialization:

1. L = length(messages)
2. M = length(committed_messages)
3. if length(disclosed_indexes) > L, return INVALID
4. for i in disclosed_indexes, if i < 0 or i >= L, return INVALID
5. if length(disclosed_commitment_indexes) > M, return INVALID
6. for j in disclosed_commitment_indexes,
                               if i < 0 or i >= M, return INVALID

Procedure:

1.  message_scalars = BBS.messages_to_scalars(messages, api_id)

2.  committed_message_scalars = ()
3.  committed_message_scalars.append(secret_prover_blind)
4.  committed_message_scalars.append(BBS.messages_to_scalars(
                                            committed_messages, api_id))


5.  generators = BBS.create_generators(length(message_scalars) + 1, api_id)
6.  blind_generators = BBS.create_generators(length(committed_message_scalars) + 1, "BLIND_" || api_id)

7.  indexes = ()
8.  indexes.append(disclosed_indexes)
9.  for j in disclosed_commitment_indexes: indexes.append(j + L + 1)

10. proof = BBS.CoreProofGen(
                     PK,
                     signature,
                     generators.append(blind_generators),
                     header,
                     ph,
                     message_scalars.append(committed_message_scalars),
                     indexes,
                     api_id)
11. return proof
```

### Proof Verification

The ProofVerify operation validates a BBS proof, given the Signer's public key (PK), a header and presentation header values, two arrays of disclosed messages (the ones known to the Signer and the ones committed by the prover) and two corresponding arrays of indexes those messages had in the original vectors of signed messages. In addition, the `BlindProofVerify` operation defined in this section accepts the integer `L`, representing the total number of signed messages known by the Signer.

This operation makes use of the `CoreProofVerify` operation as defined in [Section 3.6.4](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreproofverify) of [@!I-D.irtf-cfrg-bbs-signatures].

```
result = BlindProofVerify(PK,
                          proof,
                          header,
                          ph,
                          L,
                          disclosed_messages,
                          disclosed_committed_messages,
                          disclosed_indexes,
                          disclosed_committed_indexes)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- proof (REQUIRED), an octet string of the form outputted by the
                    ProofGen operation.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to the empty octet string ("").
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to the empty octet
                 string ("").
- L (OPTIONAL), an integer, representing the total number of Signer
                known messages if not supplied it defaults to 0.
- disclosed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied, it defaults to the empty
                                 array ("()").
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array ("()").

Parameters:

- api_id, the octet string ciphersuite_id || "H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and "H2G_HM2S_"is
          an ASCII string comprised of 9 bytes.
- (octet_point_length, octet_scalar_length), defined by the ciphersuite.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1. proof_len_floor = 2 * octet_point_length + 3 * octet_scalar_length
2. if length(proof) < proof_len_floor, return INVALID
3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
4. total_no_messages = length(disclosed_indexes) +
                                 length(disclosed_committed_indexes) + U
5. M = total_no_messages - L

Procedure:

1.  generators = BBS.create_generators(L + 1, api_id)
2.  blind_generators = BBS.create_generators(M + 1, "BLIND_" || api_id)

3.  disclosed_message_scalars = messages_to_scalars(
                                             disclosed_messages, api_id)
4.  disclosed_committed_message_scalars = messages_to_scalars(
                                   disclosed_committed_messages, api_id)
5.  message_scalars = disclosed_message_scalars.append(
                                    disclosed_committed_message_scalars)

6.  indexes = ()
7.  indexes.append(disclosed_indexes)
8.  for j in disclosed_commitment_indexes: indexes.append(j + L + 1)

9.  result = BBS.CoreProofVerify(PK,
                                 proof,
                                 generators.append(blind_generators),
                                 header,
                                 ph,
                                 message_scalars,
                                 indexes,
                                 api_id)
10. return result
```

## Core Operations

### Core Commitment Computation

```
commit_with_proof = CoreCommit(blind_generators, committed_messages, api_id)

Inputs:

- blind_generators (REQUIRED), vector of pseudo-random points in G1.
- committed_messages (OPTIONAL), a vector of scalars. If not supplied,
                                 it defaults to the empty array ("()").
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").

Deserialization:

1. M = length(committed_messages)
2. if length(blind_generators) != M + 1, return INVALID
3. (Q_2, J_1, ..., J_M) = blind_generators

Procedure:

1. (secret_prover_blind, s~, m~_1, ..., m~_M)
                                         = BBS.get_random_scalars(M + 2)
2. C = Q_2 * secret_prover_blind + J_1 * msg_1 + ... + J_M * msg_M
3. Cbar = Q_2 * s~ + J_1 * m~_1 + ... + J_M * m~_M

4. challenge = calculate_blind_challenge(C, Cbar, blind_generators,
                                                                 api_id)

5. s^ = s~ + secret_prover_blind * challenge
6. for m in (1, 2, ..., M): m^_i = m~_1 + msg_i * challenge

7. proof = (s^, (m^_1, ..., m^_M), challenge)
8. commit_with_proof = commitment_with_proof_to_octets(C, proof)
9. return (commit_with_proof, secret_prover_blind)
```

### Core Commitment Verification

This operation is used by the Signer to verify the correctness of a `commitment_proof` for a supplied `commitment`, over a list of points of G1 called the `blind_generators`, used to compute that commitment.

```
result = CoreCommitVerify(commitment, commitment_proof,
                                               blind_generators, api_id)

Inputs:

- commitment (REQUIRED), a commitment (see (#terminology)).
- commitment_proof (REQUIRED), a commitment_proof (see (#terminology)).
- blind_generators (REQUIRED), vector of pseudo-random points in G1.
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- result: either VALID or INVALID

Deserialization:

1. (s^, commitments, cp) = commitment_proof

2. M = length(commitments)
3. (m^_1, ..., m^_M) = commitments

4. if length(blind_generators) != M + 1, return INVALID
5. (Q_2, J_1, ..., J_M) = blind_generators

Procedure:

1. Cbar = Q_2 * s^ + J_1 * m^_1 + ... + J_M * m^_M + commitment * (-cp)
2. cv = calculate_blind_challenge(commitment, Cbar, blind_generators,
                                                                 api_id)
3. if cv != cp, return INVALID
4. return VALID
```

### Finalize Blind Sign

This operation computes a blind BBS signature, from a secret key (`SK`), a set of generators (points of G1), a supplied commitment with its proof of correctness (`commitment_with_proof`), a header (`header`) and a set of messages (`messages`). The operation also accepts the identifier of the BBS Interface, calling this core operation.

```
blind_signature = FinalizeBlindSign(SK,
                                    PK,
                                    B,
                                    generators,
                                    blind_generators,
                                    header,
                                    api_id)

Inputs:

- SK (REQUIRED), a secret key in the form outputted by the KeyGen
                 operation.
- PK (REQUIRED), an octet string of the form outputted by SkToPk
                 provided the above SK as input.
- B (REQUIRED), a point of G1, different than Identity_G1.
- generators (REQUIRED), vector of pseudo-random points in G1.
- blind_generators (OPTIONAL), vector of pseudo-random points in G1. If
                               not supplied it defaults to the empty
                               array.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- blind_signature, a blind signature encoded as an octet string; or
                   INVALID.

Definitions:

1. signature_dst, an octet string representing the domain separation
                  tag: api_id || "H2S_" where "H2S_" is an ASCII string
                  composed of 4 bytes.

Deserialization:

1. L = length(generators) - 1
2. M = length(blind_generators)

3. if L <= 0 or M <=0, return INVALID
4. (Q_1, H_1, ..., H_L) = generators
5. (J_1, ..., J_M) = blind_generators

Procedure:

1. domain = BBS.calculate_domain(PK, Q_1, (H_1, ..., H_L, J_1, ..., J_M),
                                                         header, api_id)
2. e_octs = serialize((SK, B, domain))
3. e = BBS.hash_to_scalar(e_octs, signature_dst)
4. A = B * (1 / (SK + e))
5. return signature_to_octets((A, e))
```

# Utilities

## Calculate B value

```
res  = B_calculate(generators, commitment, message_scalars)

Inputs:

- generators (REQUIRED), an array of at least one point from the
                         G1 group.
- commitment (OPTIONAL), a point from the G1 group. If not supplied it
                         defaults to the Identity_G1 point.
- message_scalars (OPTIONAL), an array of scalar values. If not
                              supplied, it defaults to the empty
                              array ("()").

Outputs:

- res, an array of a single element from the G1 subgroup, or INVALID.

Deserialization:

1. L = length(messages)
2. if length(generators) != L + 1, return INVALID
3. (Q_1, H_1, ..., H_L) = generators
4. (msg_1, ..., msg_L) = messages

Procedure:

1. B = Q_1 + H_1 * msg_1 + ... + H_L * msg_L + commitment
4. if B is Identity_G1, return INVALID
5. return B
```

## Blind Challenge Calculation

```
challenge = calculate_blind_challenge(C, Cbar, generators, api_id)

Inputs:

- C (REQUIRED), a point of G1.
- Cbar (REQUIRED), a point of G1.
- generators (REQUIRED), an array of points from G1, of length at
                         least 1.
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Definition:

- blind_challenge_dst, an octet string representing the domain
                       separation tag: api_id || "H2S_" where
                       ciphersuite_id is defined by the ciphersuite and
                       "H2S_" is an ASCII string composed of 4 bytes.

Deserialization:

1. if length(generators) == 0, return INVALID
2. M = length(generators) - 1

Procedure:

1. c_arr = (M)
2. c_arr.append(generators)
3. c_octs = serialize(c_arr.append(C, Cbar))
4. return BBS.hash_to_scalar(c_octs, blind_challenge_dst)
```

## Serialize

### Commitment with Proof to Octets

```
commitment_octets = commitment_with_proof_to_octets(commitment, proof)

Inputs:

- commitment (REQUIRED), a point of G1.
- proof (REQUIRED), a vector comprising of a scalar, a possibly empty
                    vector of scalars and another scalar in that order.

Outputs:

- commitment_octets, an octet string or INVALID.

Procedure:

1. commitment_octs = serialize(commitment)
2. if commitment_octs is INVALID, return INVALID
3. proof_octs = serialize(proof)
4. if proof_octs is INVALID, return INVALID
5. return commitment_octs || proof_octs
```

### Octet to Commitment with Proof

```
commitment = octets_to_commitment_with_proof(commitment_octs)

Inputs:

- commitment_octs (REQUIRED), an octet string in the form outputted from
                              the commitment_to_octets operation.

Parameters:

- (octet_point_length, octet_scalar_length), defined by the ciphersuite.

Outputs:

- commitment, a commitment in the form (C, proof), where C a point of G1
              and a proof vector comprising of a scalar, a possibly
              empty vector of scalars and another scalar in that order.

Procedure:

1.  commit_len_floor = octet_point_length + 2 * octet_scalar_length
2.  if length(commitment_octs) < commit_len_floor, return INVALID

3.  C_octets = commitment_octs[0..(octet_point_length - 1)]
4.  C = octets_to_point_g1(C_octets)
5.  if C is INVALID, return INVALID
6.  if C == Identity_G1, return INVALID

7.  j = 0
8.  index = octet_point_length
9.  while index < length(commitment_octs):
10.     end_index = index + octet_scalar_length - 1
11.     s_j = OS2IP(commitment_octets[index..end_index])
12.     if s_j = 0 or if s_j >= r, return INVALID
13.     index += octet_scalar_length
14.     j += 1

15. if index != length(commitment_octs), return INVALID
16. if j < 2, return INVALID
17. msg_commitment = ()
18. if j >= 3, set msg_commitment = (s_2, ..., s_(j-1))
19. return (C, (s_0, msg_commitments, s_j))
```

# Security Considerations

Security considerations detailed in [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-security-considerations) of [@!I-D.irtf-cfrg-bbs-signatures] apply to this draft as well.

## Prover Blind Factor

The random scalar value `secret_prover_blind` calculated and returned by the `Commit` operation is responsible for "hiding" the committed messages (otherwise, in many practical applications, the Signer may be able to retrieve them). Furthermore, it guarantees that the entity generating the BBS proof (see `BlindProofGen` defined in (#proof-generation)) has knowledge of that factor. As a result, the `secret_prover_blind` MUST remain private by the Prover and it MUST be generated using a cryptographically secure pseudo-random number generator. See [Section 6.7](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-05.html#name-randomness-requirements) of [@!I-D.irtf-cfrg-bbs-signatures] on recommendations and requirements for implementing the `BBS.get_random_scalars` operation (which is used to calculate the `secret_prover_blind` value).

## Key Binding

One natural use case for the blind signatures extension of the BBS scheme is key binding. In the context of BBS Signatures, key binding guarantees that only entities in control of a specific private key can compute BBS proofs. This can be achieved by committing to the private key prior to issuance, resulting in a BBS signature that includes that key as one of the signed messages. Creating a BBS proof from that signature will then require knowledge of that key (similar to any signed message). The Prover MUST NOT disclose that key as part of a proof generation procedure. Note also that the `secret_prover_blind` value returned by the `Commit` operation defined in (#commitment-computation) (see (#prover-blind-factor)), has a similar property, i.e., it's knowledge is required to generate a proof from a blind signature. Many applications however, requiring key binding, mandate that the same private key is used among multiple signatures, whereas the `secret_prover_blind` is uniquely generated for each blind signature issuance request. In those cases, a commitment to a private key must be used, as described above.

# Ciphersuites

This document uses the `BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_` and `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_` defined in [Section 7.2.1](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-bls12-381-shake-256) and [Section 7.2.2](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-bls12-381-sha-256) correspondingly, of [@!I-D.irtf-cfrg-bbs-signatures].

# Test Vectors

TBD


# IANA Considerations

This document does not make any requests of IANA.

{backmatter}

<reference anchor="P91" target="https://ia.cr/2023/275">
  <front>
    <title>Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing</title>
    <author initials="T." surname="Pedersen" fullname="Torden Pryds Pedersen">
      <organization>Aarhus University</organization>
    </author>
    <date year="1991"/>
  </front>
  <seriesInfo name="In" value="CRYPTO"/>
</reference>

<reference anchor="BG18" target="https://link.springer.com/chapter/10.1007/978-3-319-76581-5_19">
  <front>
    <title>Efficient Batch Zero-Knowledge Arguments for Low Degree Polynomials</title>
    <author initials="J." surname="Bootle" fullname="Jonathan Bootle">
      <organization>University College London</organization>
    </author>
    <author initials="J." surname="Groth" fullname="Jens Groth">
      <organization>University College London</organization>
    </author>
    <date year="2018"/>
  </front>
  <seriesInfo name="In" value="CRYPTO"/>
</reference>
