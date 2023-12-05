%%%
title = "Blind BBS Signatures"
abbrev = "Blind BBS Signatures"
ipr= "none"
area = "Internet"
workgroup = "none"
submissiontype = "IETF"
keyword = [""]

[seriesInfo]
name = "Individual-Draft"
value = "draft-bbs-blind-signatures-latest"
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
initials = "T."
surname = "Looker"
fullname = "Tobias Looker"
#role = "editor"
organization = "MATTR"
  [author.address]
  email = "tobias.looker@mattr.global"

[[author]]
initials = "A."
surname = "Whitehead"
fullname = "Andrew Whitehead"
#role = "editor"
organization = "Portage"
  [author.address]
  email = "andrew.whitehead@portagecybertech.com"
%%%

.# Abstract

This document defines an extension to the BBS Signature scheme that supports blind digital signatures, i.e., signatures over messages not known to the Signer of that signature.

{mainmatter}

# Introduction

The BBS Signatures scheme, as defined in [@!I-D.irtf-cfrg-bbs-signatures] can be extended to support blind signatures functionality. In a blind signatures setting, the Prover wants to get a BBS signature over a list of messages, without revealing those messages to the Signer. To do that, they construct a "hiding" commitment to those messages (i.e., a commitment which reveals no information about the committed values), together with a proof of correctness of that commitment. They will then send the (commitment, proof) pair to the Signer. Upon receiving that pair, the Signer will first have to verify the proof of correctness of the commitment. If the commitment is valid, they will then be able to use it in generating a BBS signature. The resulting signature will be a valid BBS signature over the messages committed by the Prover. The Signer can optionally include messages to the signature, in addition to the ones committed by the prover. Upon receiving the blind BBS signature, the Prover can verify it using the messages they committed to together with the messages the Signer included to the signature, and then use it to generate BBS proofs normally, as described in [@!I-D.irtf-cfrg-bbs-signatures].

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
  |  Signer  |                                          |  Holder/  |
  |          |-------(4)* Send signature + msgs-------->|  Prover   |
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
                                                        | Verifier  |
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
: A zero knowledge proof of correctness of a commitment, consisting from a scalar value, a possibly empty set of scalars (of length equal to the number of committed\_messages, see above) and another scalar, in that order.

prover\_blind
: A random scalar used to blind (i.e., randomize) the commitment constructed by the prover.

signer\_blind
: A random scalar used by the signer to optionally re-blind the received commitment.

## Notation

Notation defined by [@!I-D.irtf-cfrg-bbs-signatures] applies to this draft.

Additionally, the following notation and primitives are used:

list.append(elements)
: Append either a single element or a list of elements to the end of a list, maintaining the same order of the list's elements as well as the appended elements. For example, given `list = [a, b, c]` and `elements = [d, a]`, then `list.append(elements) = [a, b, c, d, a]`.

# Conventions

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when they appear in this
document, are to be interpreted as described in [@!RFC2119].

# BBS Signature Scheme Operations

This document makes use of various operations defined by the BBS Signature Scheme document [@!I-D.irtf-cfrg-bbs-signatures]. For clarity, whenever an operation will be used defined in [@!I-D.irtf-cfrg-bbs-signatures], it will be prefixed by "BBS." (e.g., "BBS.CoreProofGen" etc.). More specifically, the operations used are the following:

- `BBS.CoreVerify`: Refers to the `CoreVerify` operation defined in [Section 3.6.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-coreverify) of [@!I-D.irtf-cfrg-bbs-signatures].
- `BBS.CoreProofGen`: Refers to the `CoreProofGen` operation defined in [Section 3.6.3](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-coreproofgen) of [@!I-D.irtf-cfrg-bbs-signatures].
- `BBS.create_generators`: Refers to the `create_generators` operation defined in [Section 4.1.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-generators-calculation) of [@!I-D.irtf-cfrg-bbs-signatures].
- `BBS.messages_to_scalars`: Refers to the `messages_to_scalars` operation defined in [Section 4.1.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-messages-to-scalars) of [@!I-D.irtf-cfrg-bbs-signatures].
- `BBS.get_random_scalars`: Refers to the `get_random_scalars` operation defined in [Section 4.2.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-random-scalars) of [@!I-D.irtf-cfrg-bbs-signatures].

# Scheme Definition

## Commitment Operations

### Commitment Computation

This operation is used by the Prover to create `commitment` to a set of messages (`committed_messages`), that they intent to include to the signature. Note that this operation returns both the serialized combination of the commitment and its proof of correctness (`commitment_with_proof`), as well as the random scalar used to blind the commitment (`prover_blind`).

```
(commitment_with_proof, prover_blind) = Commit(committed_messages,
                                                                 api_id)

Inputs:

- committed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied it defaults to the empty
                                 array "()".
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- (commitment_with_proof, prover_blind), a tuple comprising from an
                                         octet string and a random
                                         scalar in that order.

Procedure:

1.  M = length(messages)
2.  generators = BBS.create_generators(M + 2, api_id)
3.  (Q_2, J_1, ..., J_M) = generators[1..M+1]

4.  (msg_1, ..., msg_M) = BBS.messages_to_scalars(committed_messages,
                                                                 api_id)
5.  (prover_blind, s~, m~_1, ..., m~_M) = BBS.get_random_scalars(M + 2)

6.  C = Q_2 * prover_blind + J_1 * msg_1 + ... + J_M * msg_M
7.  Cbar = Q_2 * s~ + J_1 * m~_1 + ... + J_M * m~_M

8.  challenge = calculate_blind_challenge(C, Cbar, generators, api_id)

9.  s^ = s~ + prover_blind * challenge
10. for m in (1, 2, ..., M): m^_i = m~_1 + msg_i * challenge
11. proof = (s^, (m^_1, ..., m^_M), challenge)
12. commit_with_proof_octs = commitment_with_proof_to_octets(C, proof)
13. return (commit_with_proof_octs, prover_blind)
```

### Commitment Verification

This operation is used by the Signer to verify the correctness of a `commitment_proof` for a supplied `commitment`, over a list of points of G1 called the `blind_generators`, used to generate that commitment.

```
result = verify_commitment(commitment, commitment_proof,
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

## Blind BBS Signatures Interface

The following section defines a BBS Interface for blind BBS signatures. The identifier of the Interface is defined as `ciphersuite_id || BLIND_H2G_HM2S_`, where `ciphersuite_id` the unique identifier of the BBS ciphersuite used, as is defined in [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]). Each BBS Interface MUST define operations to map the inputted messages to scalar values and to create the generators set, required by the core operations. The inputted messages to the defined Interface will be mapped to scalars using the `messages_to_scalars` operation defined in [Section 4.1.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-messages-to-scalars) of [@!I-D.irtf-cfrg-bbs-signatures]. The generators will be created using the `create_generators` operation defined in Section [Section 4.1.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-generators-calculation) of [@!I-D.irtf-cfrg-bbs-signatures].

Other than the `BlindSign` operation defined in (#blind-signature-generation), which uses the `CoreBlindSign` procedure, defined in (#core-blind-sign), all other interface operations defined in this section use the core operations defined in [Section 3.6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-core-operations) of [@!I-D.irtf-cfrg-bbs-signatures].

### Blind Signature Generation

This operation returns a BBS blind signature from a secret key (SK), over a header, a set of messages and optionally a commitment value (see (#terminology)). If supplied, the commitment value must be accompanied by its proof of correctness (`commitment_with_proof`), as the first element outputted by the `Commit` operation ((#commitment-computation)). The issuer can also further randomize the supplied commitment, by supplying a random scalar (`signer_blind`), that MUST be computed as,

```
signer_blind = BBS.get_random_scalars(1)
```

If the `signer_blind` input is not supplied, it will default to the zero scalar (`0`).

The `BlindSign` operation makes use of the `CoreBlindSign` procedure defined in (#core-blind-sign).

```
blind_signature = BlindSign(SK, PK, commitment_with_proof, header,
                                                 messages, signer_blind)

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
                     to an empty string.
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array "()".
- signer_blind (OPTIONAL), a random scalar value. If not supplied it
                           defaults to zero "0".

Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string comprised of 15 bytes.
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

1. generators = BBS.create_generators(M + L + 1, api_id)

2. message_scalars = BBS.messages_to_scalars(messages, api_id)

3. blind_sig = CoreBlindSign(SK,
                             PK,
                             commitment_with_proof,
                             generators,
                             header,
                             messages,
                             signer_blind,
                             api_id)
4. if blind_sig is INVALID, return INVALID
5. return blind_sig
```

### Blind Signature Verification

This operation validates a blind BBS signature (`signature`), given the Signer's public key (`PK`), a header (`header`), a set of known to the Signer messages (`messages`) and if used, a set of committed messages (`committed_messages`), the `prover_blind` as returned by the `Commit` operation ((#commitment-computation)) and a blind factor supplied by the Signer (`signer_blind`).

This operation makes use of the `CoreVerify` operation as defined in [Section 3.6.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-coreverify) of [@!I-D.irtf-cfrg-bbs-signatures].

```
result = Verify(PK, signature, header, messages, committed_messages,
                                             prover_blind, signer_blind)

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
- prover_blind (OPTIONAL), a scalar value. If not supplied it defaults
                           to zero "0".
- signer_blind (OPTIONAL), a scalar value. If not supplied it defaults
                           to zero "0".


Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string comprised of 15 bytes.

Outputs:

- result: either VALID or INVALID

Deserialization:

1. L = length(messages)
2. M = length(committed_messages)

Procedure:

1. message_scalars = ()
2. if prover_blind != 0, message_scalars.append(
                                            prover_blind + signer_blind)
3. message_scalars.append(BBS.messages_to_scalars(
                                            committed_messages, api_id))
4. message_scalars.append(BBS.messages_to_scalars(messages, api_id))

5. generators = BBS.create_generators(length(message_scalars) + 1,
                                                                 api_id)
6. res = BBS.CoreVerify(PK, signature, generators, header, messages,
                                                                 api_id)
7. return res
```

### Proof Generation

This operation creates a BBS proof, which is a zero-knowledge, proof-of-knowledge, of a BBS signature, while optionally disclosing any subset of the signed messages. Note that in contrast to the `ProofGen` operation of [@!I-D.irtf-cfrg-bbs-signatures] (see [Section 3.5.3](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-generation-proofgen)), the `ProofGen` operation defined in this section accepts 2 different lists of messages and disclosed indexes, one for the messages known to the Signer (`messages`) and teh corresponding disclosed indexes (`disclosed_indexes`) and one for the messages committed by the Prover (`committed_messages`) and the corresponding disclosed indexes (`disclosed_commitment_indexes`).

To Verify a proof however, the Verifier expects only one list of messages and one list of disclosed indexes (see (#proof-verification)). This is done to avoid revealing which of the disclosed messages where committed by the Prover and which are known to the Verifier. To this end, the `BlindProofGen` operation defined in this section, uses the `get_disclosed_data` defined in (#present-and-verify-a-bbs-proof) to combine and return the disclosed messages and the disclosed indexes that the prover should present to the Verifier.

Lastly, the the operation also expects the `prover_blind` (as returned from the `Commit` operation defined in (#commitment-computation)) and `signer_blind` (as inputted in the `BlindSign` operation defined in (#blind-signature-generation)) values. If the BBS signature is generated using a commitment value, then the `prover_blind` returned by the `Commit` operation used to generate the commitment should be provided to the `ProofGen` operation (otherwise the resulting proof will be invalid).

Note that the `BlindProofGen` operation defined in this section returns both the generated proof as an octet string, together with a vector (`disclosed_data`) containing all the disclosed messages and their indexes, that would be later revealed to the proof Verifier.

This operation makes use of the `CoreProofGen` operation as defined in [Section 3.6.3](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-04.html#name-coreproofgen) of [@!I-D.irtf-cfrg-bbs-signatures].

```
(proof, disclosed_msgs, disclosed_idxs)
                           = BlindProofGen(PK,
                                           signature,
                                           header,
                                           ph,
                                           messages,
                                           committed_messages,
                                           disclosed_indexes,
                                           disclosed_commitment_indexes,
                                           prover_blind,
                                           signer_blind)

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
- prover_blind (OPTIONAL), a scalar value. If not supplied it defaults
                           to zero "0".
- signer_blind (OPTIONAL), a scalar value. If not supplied it defaults
                           to zero "0".


Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string comprised of 15 bytes.

Outputs:

- (proof, disclosed_msgs, disclosed_idxs) a tuple comprising from an
                                          octet string, an array of
                                          octet strings and an array of
                                          non-zero integers; or INVALID.

Deserialization:

1. L = length(messages)
2. M = length(committed_messages)
3. if length(disclosed_indexes) > L, return INVALID
4. for i in disclosed_indexes, if i < 0 or i >= L, return INVALID
5. if length(disclosed_commitment_indexes) > M, return INVALID
6. for j in disclosed_commitment_indexes,
                               if i < 0 or i >= L, return INVALID

Procedure:

1.  message_scalars = ()
2.  if prover_blind != 0, message_scalars.append(
                                            prover_blind + signer_blind)

4.  message_scalars.append(BBS.messages_to_scalars(
                                   committed_messages, api_id))
5.  message_scalars.append(BBS.messages_to_scalars(messages, api_id))

6.  generators = BBS.create_generators(length(message_scalars) + 1,
                                                                 api_id)
7.  disclosed_data = get_disclosed_data(
                                  messages,
                                  committed_messages,
                                  disclosed_indexes,
                                  disclosed_commitment_indexes,
                                  commitment_used)
8.  if disclosed_data is INVALID, return INVALID.
9.  (disclosed_msgs, disclosed_idxs) = disclosed_data

10. proof = BBS.CoreProofGen(PK, signature, generators, header, ph,
                                message_scalars, disclosed_idxs, api_id)
11. return (proof, disclosed_msgs, disclosed_idxs)
```

### Proof Verification

To verify a proof generated by the `BlindProofGen` operation defined in (#proof-generation), the Verifier can directly use the `ProofVerify` operation defined in [Section 3.5.4](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-verification-proofver) of [@!I-D.irtf-cfrg-bbs-signatures], instantiated with the following parameter

```
api_id = ciphersuite_id || "BLIND_H2G_HM2S_", where ciphersuite_id is
         defined by the ciphersuite and "BLIND_H2G_HM2S_"is an ASCII
         string comprised of 15 bytes.
```

The purpose of the above, is to reduce the information a Verifier may get, regarding which of the disclosed messages where committed by the Prover and which where known to the Issuer. For this purpose, the Prover MUST follow the procedure described in (#present-and-verify-a-bbs-proof) to prepare the data that will be supplied to the proof Verifier.

## Core Operations

### Core Blind Sign

This operation computes a blind BBS signature, from a secret key (`SK`), a set of generators (points of G1), a supplied commitment with its proof of correctness (`commitment_with_proof`), a header (`header`) and a set of messages (`messages`). The operation also accepts a random scalar (`signer_blind`) and the identifier of the BBS Interface, calling this core operation.

```
blind_signature = CoreBlindSign(SK,
                                PK,
                                generators,
                                commitment_with_proof,
                                header,
                                messages,
                                signer_blind,
                                api_id)

Inputs:

- SK (REQUIRED), a secret key in the form outputted by the KeyGen
                 operation.
- PK (REQUIRED), an octet string of the form outputted by SkToPk
                 provided the above SK as input.
- generators (REQUIRED), vector of pseudo-random points in G1.
- commitment_with_proof (OPTIONAL), an octet string, representing a
                                    serialized commitment and
                                    commitment_proof, as the first
                                    element outputted by the Commit
                                    operation. If not supplied, it
                                    defaults to the empty string ("").
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array "()".
- signer_blind (OPTIONAL), a random scalar value. If not supplied it
                           defaults to zero "0".

Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string comprised of 15 bytes.

Outputs:

- blind_signature, a blind signature encoded as an octet string; or
                   INVALID.

Definitions:

1. signature_dst, an octet string representing the domain separation
                  tag: api_id || "H2S_" where "H2S_" is an ASCII string
                  comprised of 4 bytes.

Deserialization:

1. L = length(messages)
2. (msg_1, ..., msg_L) = messages

3. commit_res = deserialize_and_validate_commit(commitment_with_proof,
                                                generators,
                                                api_id)
4. if commit_res is INVALID, return INVALID

// if commitment_with_proof == "", then commit_res = (Identity_G1, 0).
4. (commit, M) = commit_res

5. Q_1 = generators[0]
6. commitment_with_proof != "", Q_2 = generators[1]

7. (H_1, ..., H_L) = generators[M + 1..M + L + 1]

Procedure:

1. domain = calculate_domain(PK, generators, header, api_id)

2. e_octs = serialize((SK, domain, msg_1, ..., msg_L, signer_blind))
3. e = hash_to_scalar(e_octs || commitment_with_proof, signature_dst)

// if a commitment is not supplied, Q_2 = Identity_G1, meaning that
// signer_blind will be ignored.
4. commit = commit + Q_2 * signer_blind
5. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L + commit
6. A = B * (1 / (SK + e))
7. return signature_to_octets((A, e))

8. return signature
```


# Present and Verify a BBS Proof

To avoid revealing to the proof Verifier which messages are committed to the signature, and which where known to the Signer, after calculating a BBS proof, the Prover will need to combine the disclosed committed messages as well as the disclosed messages known to the Signer to a single disclosed messages list. The same holds for the disclosed message indexes, where the ones corresponding to committed messages and the ones corresponding to messages known by the Signer should be combined together. To do that, the Prover MUST follow the following operation.

```
disclosed_data = get_disclosed_data(messages,
                                    committed_messages,
                                    disclosed_indexes,
                                    disclosed_commitment_indexes)

Inputs:

- messages (OPTIONAL), vector of scalars. If not supplied, it defaults
                       to the empty array "()".
- committed_messages (OPTIONAL), vector of scalars. If not supplied, it
                                 defaults to the empty array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".
- disclosed_commitment_indexes (OPTIONAL), vector of unsigned integers
                                           in ascending order. Indexes
                                           of disclosed messages. If not
                                           supplied, it defaults to the
                                           empty array "()".

Outputs

- disclosed_data, a vector comprising of two vectors, one corresponding
                  to the disclosed messages and one to the disclosed
                  indexes.

Deserialization:

1. L = length(disclosed_indexes)
2. M = length(committed_messages)
3. (i1, ..., iL) = disclosed_indexes
4. (j1, ...., jL) = disclosed_commitment_indexes

5. if length(messages) < L, return INVALID
6. if length(committed_messages) < M, return INVALID

Procedure:

// combine the disclosed indexes
3. indexes = ()
4. for i in disclosed_commitment_indexes: indexes.append(i + 1)
5. for j in disclosed_indexes: indexes.append(M + j + 1)

// combine the revealed messages
6. disclosed_messages = (messages[i1], ..., messages[iL])
7. disclosed_committed_messages = (committed_messages[j1], ...
                                            ..., committed_messages[jM])
8. disclosed_messages.append(disclosed_committed_messages)

9. return (disclosed_messages, indexes)
```

# Utilities

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
                       "H2S_" is an ASCII string comprised of 4 bytes.

Deserialization:

1. if length(generators) == 0, return INVALID
2. M = length(generators) - 1

Procedure:

1. c_arr = (C, Cbar, M)
2. c_arr.append(generators)
3. c_octs = serialize(c_arr)
4. return hash_to_scalar(c_octs, blind_challenge_dst)
```

##  Commitment Validation and Deserialization

The following is a helper operation used by the `CoreBlindSign` procedure ((#core-blind-sign)) to validate an optional commitment. The `commitment` input to `CoreBlindSign` is optional. If a `commitment` is not supplied, or if it is the `Identity_G1`, the following operation will return the `Identity_G1` as the commitment point, which will be ignored by all computations during `CoreBlindSign`.

```
(commit, blind_gen_no) = deserialize_and_validate_commit(
                                                  commitment_with_proof,
                                                  generators,
                                                  api_id)

Inputs:

- commitment_with_proof (OPTIONAL), octet string. If it is not supplied
                                    it defaults to the empty octet
                                    string ("").
- generators (OPTIONAL), vector of points of G1. If it is not supplied
                         it defaults to the empty set ("()").
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- (commit, blind_gen_no), a tuple comprising from commitment, a
                          commitment_proof (see (#terminology)), in that
                          order; or INVALID.

Procedure:

1.  if commitment_with_proof is the empty string (""), return
                                                    (Identity_G1, 0)

2.  com_res = octets_to_commitment_with_proof(commitment_with_proof)
3.  if com_res is INVALID, return INVALID

4.  (commit, commit_proof) = com_res
5.  M = length(commit_proof[1]) + 1

6.  if length(generators) < M + 1, return INVALID
7.  blind_generators = generators[1..M + 1]

8.  validation_res = verify_commitment(COMMIT, commit_proof,
                                               blind_generators, api_id)
9.  if validation_res is INVALID, return INVALID
10. (commitment, M)
```

## Serialize

### Commitment with Proof to Octets

```
commitment_octets = commitment_with_proof_to_octets(commitment, proof) If the proof is INVALID,

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
              and proof a vector comprising of a scalar, a possibly
              empty vector of scalars and another scalar in that order.

Procedure:

1.  commit_len_floor = octet_point_length + 2 * octet_scalar_length
2.  if length(commitment) < commit_len_floor, return INVALID

3.  C_octets = commitment_octs[0..(octet_point_length - 1)]
4.  C = octets_to_point_g1(C_octets)
5.  if C is INVALID, return INVALID
6.  if C == Identity_G1, return INVALID

7.  j = 0
8.  index = octet_point_length
9.  while index < length(commitment_octs):
10.     end_index = index + octet_scalar_length - 1
11.     s_j = OS2IP(proof_octets[index..end_index])
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

// TODO

# Ciphersuites

This document uses the `BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_` and `BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_` defined in [Section 6.2.1](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-bls12-381-shake-256) and [Section 6.2.2](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-bls12-381-sha-256) correspondingly, of [@!I-D.irtf-cfrg-bbs-signatures].

# Test Vectors

## BLS12-381-SHAKE-256 Test Vectors

### Commitment

#### No Committed Messages

```
Mocked RNG parameters:
    dst = {{ $commitmentFixtures.bls12-381-shake-256.commit001.mockRngParameters.commit.DST }}
    count =  {{ $commitmentFixtures.bls12-381-shake-256.commit001.mockRngParameters.commit.count }}

committed_messages = {{ $commitmentFixtures.bls12-381-shake-256.commit001.committedMessages }}
prover_blind = {{ $commitmentFixtures.bls12-381-shake-256.commit001.proverBlind }}
commitment_with_proof = {{ $commitmentFixtures.bls12-381-shake-256.commit001.commitmentWithProof }}
```

#### Multiple Committed Messages


```
Mocked RNG parameters:
    dst = {{ $commitmentFixtures.bls12-381-shake-256.commit002.mockRngParameters.commit.DST }}
    countsource ~./ =  {{ $commitmentFixtures.bls12-381-shake-256.commit002.mockRngParameters.commit.count }}

committed_message_1 = {{ $commitmentFixtures.bls12-381-shake-256.commit002.committedMessages[0] }}
committed_message_2 = {{ $commitmentFixtures.bls12-381-shake-256.commit002.committedMessages[1] }}
committed_message_3 = {{ $commitmentFixtures.bls12-381-shake-256.commit002.committedMessages[2] }}
committed_message_4 = {{ $commitmentFixtures.bls12-381-shake-256.commit002.committedMessages[3] }}
committed_message_5 = {{ $commitmentFixtures.bls12-381-shake-256.commit002.committedMessages[4] }}

prover_blind = {{ $commitmentFixtures.bls12-381-shake-256.commit002.proverBlind }}
commitment_with_proof = {{ $commitmentFixtures.bls12-381-shake-256.commit002.commitmentWithProof }}
```

### Signature

#### No Committed Messages, No Signer Messages

```
Mocked RNG parameters for commitment:
    dst = {{ $signatureFixtures.bls12-381-shake-256.signature001.mockRngParameters.commit.DST }}
    count =  {{ $signatureFixtures.bls12-381-shake-256.signature001.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-shake-256.signature001.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-shake-256.signature001.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-shake-256.signature001.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-shake-256.signature001.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-shake-256.signature001.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-shake-256.signature001.header }}

messages = {{ $signatureFixtures.bls12-381-shake-256.signature001.messages }}

committed_messages = {{ $signatureFixtures.bls12-381-shake-256.signature001.committedMessages }}

prover_blind = {{ $signatureFixtures.bls12-381-shake-256.signature001.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-shake-256.signature001.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-shake-256.signature001.signature }}
```

#### Multiple Prover Committed Messages, No Signer Messages

```
Mocked RNG parameters for commitment:
    dst = {{ $signatureFixtures.bls12-381-shake-256.signature002.mockRngParameters.commit.DST }}
    count =  {{ $signatureFixtures.bls12-381-shake-256.signature002.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-shake-256.signature002.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-shake-256.signature002.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-shake-256.signature002.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-shake-256.signature002.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-shake-256.signature002.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-shake-256.signature002.header }}

messages = {{ $signatureFixtures.bls12-381-shake-256.signature002.messages }}

committed_message_1 = {{ $signatureFixtures.bls12-381-shake-256.signature002.committedMessages[0] }}
committed_message_2 = {{ $signatureFixtures.bls12-381-shake-256.signature002.committedMessages[1] }}
committed_message_3 = {{ $signatureFixtures.bls12-381-shake-256.signature002.committedMessages[2] }}
committed_message_4 = {{ $signatureFixtures.bls12-381-shake-256.signature002.committedMessages[3] }}
committed_message_5 = {{ $signatureFixtures.bls12-381-shake-256.signature002.committedMessages[4] }}

prover_blind = {{ $signatureFixtures.bls12-381-shake-256.signature002.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-shake-256.signature002.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-shake-256.signature002.signature }}
```

#### No Prover Committed Messages, Multiple Signer Messages

```
Mocked RNG parameters for commitment:
    dst = {{ $signatureFixtures.bls12-381-shake-256.signature003.mockRngParameters.commit.DST }}
    count =  {{ $signatureFixtures.bls12-381-shake-256.signature003.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-shake-256.signature003.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-shake-256.signature003.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-shake-256.signature003.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-shake-256.signature003.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-shake-256.signature003.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-shake-256.signature003.header }}

messages_1 = {{ $signatureFixtures.bls12-381-shake-256.signature003.messages[0] }}
messages_2 = {{ $signatureFixtures.bls12-381-shake-256.signature003.messages[1] }}
messages_3 = {{ $signatureFixtures.bls12-381-shake-256.signature003.messages[2] }}
messages_4 = {{ $signatureFixtures.bls12-381-shake-256.signature003.messages[3] }}
messages_5 = {{ $signatureFixtures.bls12-381-shake-256.signature003.messages[4] }}
messages_6 = {{ $signatureFixtures.bls12-381-shake-256.signature003.messages[5] }}
messages_7 = {{ $signatureFixtures.bls12-381-shake-256.signature003.messages[6] }}
messages_8 = {{ $signatureFixtures.bls12-381-shake-256.signature003.messages[7] }}
messages_9 = {{ $signatureFixtures.bls12-381-shake-256.signature003.messages[8] }}
messages_10 = {{ $signatureFixtures.bls12-381-shake-256.signature003.messages[9] }}

committed_message = {{ $signatureFixtures.bls12-381-shake-256.signature003.committedMessages }}

prover_blind = {{ $signatureFixtures.bls12-381-shake-256.signature003.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-shake-256.signature003.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-shake-256.signature003.signature }}
```

#### Multiple Prover Committed and Signer Messages

```
Mocked RNG parameters for commitment:
    dst = {{ $signatureFixtures.bls12-381-shake-256.signature004.mockRngParameters.commit.DST }}
    count =  {{ $signatureFixtures.bls12-381-shake-256.signature004.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-shake-256.signature004.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-shake-256.signature004.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-shake-256.signature004.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-shake-256.signature004.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-shake-256.signature004.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-shake-256.signature004.header }}

messages_1 = {{ $signatureFixtures.bls12-381-shake-256.signature004.messages[0] }}
messages_2 = {{ $signatureFixtures.bls12-381-shake-256.signature004.messages[1] }}
messages_3 = {{ $signatureFixtures.bls12-381-shake-256.signature004.messages[2] }}
messages_4 = {{ $signatureFixtures.bls12-381-shake-256.signature004.messages[3] }}
messages_5 = {{ $signatureFixtures.bls12-381-shake-256.signature004.messages[4] }}
messages_6 = {{ $signatureFixtures.bls12-381-shake-256.signature004.messages[5] }}
messages_7 = {{ $signatureFixtures.bls12-381-shake-256.signature004.messages[6] }}
messages_8 = {{ $signatureFixtures.bls12-381-shake-256.signature004.messages[7] }}
messages_9 = {{ $signatureFixtures.bls12-381-shake-256.signature004.messages[8] }}
messages_10 = {{ $signatureFixtures.bls12-381-shake-256.signature004.messages[9] }}

committed_message_1 = {{ $signatureFixtures.bls12-381-shake-256.signature004.committedMessages[0] }}
committed_message_2 = {{ $signatureFixtures.bls12-381-shake-256.signature004.committedMessages[1] }}
committed_message_3 = {{ $signatureFixtures.bls12-381-shake-256.signature004.committedMessages[2] }}
committed_message_4 = {{ $signatureFixtures.bls12-381-shake-256.signature004.committedMessages[3] }}
committed_message_5 = {{ $signatureFixtures.bls12-381-shake-256.signature004.committedMessages[4] }}

prover_blind = {{ $signatureFixtures.bls12-381-shake-256.signature004.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-shake-256.signature004.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-shake-256.signature004.signature }}
```

#### Multiple Prover Committed and Signer Messages, No Signer Blind

```
Mocked RNG parameters for commitment:
    dst = {{ $signatureFixtures.bls12-381-shake-256.signature005.mockRngParameters.commit.DST }}
    count =  {{ $signatureFixtures.bls12-381-shake-256.signature005.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-shake-256.signature005.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-shake-256.signature005.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-shake-256.signature005.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-shake-256.signature005.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-shake-256.signature005.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-shake-256.signature005.header }}

messages_1 = {{ $signatureFixtures.bls12-381-shake-256.signature005.messages[0] }}
messages_2 = {{ $signatureFixtures.bls12-381-shake-256.signature005.messages[1] }}
messages_3 = {{ $signatureFixtures.bls12-381-shake-256.signature005.messages[2] }}
messages_4 = {{ $signatureFixtures.bls12-381-shake-256.signature005.messages[3] }}
messages_5 = {{ $signatureFixtures.bls12-381-shake-256.signature005.messages[4] }}
messages_6 = {{ $signatureFixtures.bls12-381-shake-256.signature005.messages[5] }}
messages_7 = {{ $signatureFixtures.bls12-381-shake-256.signature005.messages[6] }}
messages_8 = {{ $signatureFixtures.bls12-381-shake-256.signature005.messages[7] }}
messages_9 = {{ $signatureFixtures.bls12-381-shake-256.signature005.messages[8] }}
messages_10 = {{ $signatureFixtures.bls12-381-shake-256.signature005.messages[9] }}

committed_message_1 = {{ $signatureFixtures.bls12-381-shake-256.signature005.committedMessages[0] }}
committed_message_2 = {{ $signatureFixtures.bls12-381-shake-256.signature005.committedMessages[1] }}
committed_message_3 = {{ $signatureFixtures.bls12-381-shake-256.signature005.committedMessages[2] }}
committed_message_4 = {{ $signatureFixtures.bls12-381-shake-256.signature005.committedMessages[3] }}
committed_message_5 = {{ $signatureFixtures.bls12-381-shake-256.signature005.committedMessages[4] }}

prover_blind = {{ $signatureFixtures.bls12-381-shake-256.signature005.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-shake-256.signature005.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-shake-256.signature005.signature }}
```

#### No Commitment Signature

```
Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-shake-256.signature006.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-shake-256.signature006.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-shake-256.signature006.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-shake-256.signature006.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-shake-256.signature006.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-shake-256.signature006.header }}

messages_1 = {{ $signatureFixtures.bls12-381-shake-256.signature006.messages[0] }}
messages_2 = {{ $signatureFixtures.bls12-381-shake-256.signature006.messages[1] }}
messages_3 = {{ $signatureFixtures.bls12-381-shake-256.signature006.messages[2] }}
messages_4 = {{ $signatureFixtures.bls12-381-shake-256.signature006.messages[3] }}
messages_5 = {{ $signatureFixtures.bls12-381-shake-256.signature006.messages[4] }}
messages_6 = {{ $signatureFixtures.bls12-381-shake-256.signature006.messages[5] }}
messages_7 = {{ $signatureFixtures.bls12-381-shake-256.signature006.messages[6] }}
messages_8 = {{ $signatureFixtures.bls12-381-shake-256.signature006.messages[7] }}
messages_9 = {{ $signatureFixtures.bls12-381-shake-256.signature006.messages[8] }}
messages_10 = {{ $signatureFixtures.bls12-381-shake-256.signature006.messages[9] }}

committed_message = {{ $signatureFixtures.bls12-381-shake-256.signature006.committedMessages }}

prover_blind = {{ $signatureFixtures.bls12-381-shake-256.signature006.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-shake-256.signature006.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-shake-256.signature006.signature }}
```

### Proof

#### All Prover Committed Messages and Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof001.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof001.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof001.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof001.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof001.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof001.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-shake-256.proof001.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-shake-256.proof001.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof001.signature }}

header = {{ $proofFixtures.bls12-381-shake-256.proof001.header }}
ph = {{ $proofFixtures.bls12-381-shake-256.proof001.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-shake-256.proof001.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-shake-256.proof001.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof001.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-shake-256.proof001.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-shake-256.proof001.disclosedData }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof001.proof }}
```

#### Half Prover Committed Messages and All Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof002.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof002.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof002.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof002.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof002.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof002.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-shake-256.proof002.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-shake-256.proof002.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof002.signature }}

header = {{ $proofFixtures.bls12-381-shake-256.proof002.header }}
ph = {{ $proofFixtures.bls12-381-shake-256.proof002.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-shake-256.proof002.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-shake-256.proof002.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof002.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-shake-256.proof002.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-shake-256.proof002.disclosedData }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof002.proof }}
```

#### All Prover Committed Messages and Half Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof003.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof003.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof003.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof003.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof003.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof003.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-shake-256.proof003.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-shake-256.proof003.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof003.signature }}

header = {{ $proofFixtures.bls12-381-shake-256.proof003.header }}
ph = {{ $proofFixtures.bls12-381-shake-256.proof003.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-shake-256.proof003.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-shake-256.proof003.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof003.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-shake-256.proof003.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-shake-256.proof003.disclosedData }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof003.proof }}
```

#### Half Prover Committed Messages and Half Signer Messages

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof004.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof004.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof004.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof004.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof004.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof004.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-shake-256.proof004.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-shake-256.proof004.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof004.signature }}

header = {{ $proofFixtures.bls12-381-shake-256.proof004.header }}
ph = {{ $proofFixtures.bls12-381-shake-256.proof004.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-shake-256.proof004.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-shake-256.proof004.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof004.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-shake-256.proof004.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-shake-256.proof004.disclosedData }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof004.proof }}
```

#### No Prover Committed Messages and Half Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof005.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof005.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof005.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof005.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof005.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof005.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-shake-256.proof005.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-shake-256.proof005.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof005.signature }}

header = {{ $proofFixtures.bls12-381-shake-256.proof005.header }}
ph = {{ $proofFixtures.bls12-381-shake-256.proof005.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-shake-256.proof005.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-shake-256.proof005.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof005.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-shake-256.proof005.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-shake-256.proof005.disclosedData }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof005.proof }}
```

#### Half Prover Committed Messages and No Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof006.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof006.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof006.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof006.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof006.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof006.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-shake-256.proof006.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-shake-256.proof006.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof006.signature }}

header = {{ $proofFixtures.bls12-381-shake-256.proof006.header }}
ph = {{ $proofFixtures.bls12-381-shake-256.proof006.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-shake-256.proof006.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-shake-256.proof006.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof006.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-shake-256.proof006.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-shake-256.proof006.disclosedData }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof006.proof }}
```

#### No Prover Committed Messages and No Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof007.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof007.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof007.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof007.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof007.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof007.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-shake-256.proof007.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-shake-256.proof007.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof007.signature }}

header = {{ $proofFixtures.bls12-381-shake-256.proof007.header }}
ph = {{ $proofFixtures.bls12-381-shake-256.proof007.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-shake-256.proof007.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-shake-256.proof007.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof007.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-shake-256.proof007.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-shake-256.proof007.disclosedData }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof007.proof }}
```

#### No Commitment and Half Signer Messages Disclosed

```
Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof008.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof008.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-shake-256.proof008.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-shake-256.proof008.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-shake-256.proof008.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-shake-256.proof008.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof008.signature }}

header = {{ $proofFixtures.bls12-381-shake-256.proof008.header }}
ph = {{ $proofFixtures.bls12-381-shake-256.proof008.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-shake-256.proof008.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-shake-256.proof008.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof008.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-shake-256.proof008.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-shake-256.proof008.disclosedData }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof008.proof }}
```

## BLS12-381-SHA-256 Test Vectors

### Commitment

#### No Committed Messages

```
Mocked RNG parameters:
    dst = {{ $commitmentFixtures.bls12-381-sha-256.commit001.mockRngParameters.commit.DST }}
    count =  {{ $commitmentFixtures.bls12-381-sha-256.commit001.mockRngParameters.commit.count }}

committed_messages = {{ $commitmentFixtures.bls12-381-sha-256.commit001.committedMessages }}
prover_blind = {{ $commitmentFixtures.bls12-381-sha-256.commit001.proverBlind }}
commitment_with_proof = {{ $commitmentFixtures.bls12-381-sha-256.commit001.commitmentWithProof }}
```

#### Multiple Committed Messages


```
Mocked RNG parameters:
    dst = {{ $commitmentFixtures.bls12-381-sha-256.commit002.mockRngParameters.commit.DST }}
    count =  {{ $commitmentFixtures.bls12-381-sha-256.commit002.mockRngParameters.commit.count }}

committed_message_1 = {{ $commitmentFixtures.bls12-381-sha-256.commit002.committedMessages[0] }}
committed_message_2 = {{ $commitmentFixtures.bls12-381-sha-256.commit002.committedMessages[1] }}
committed_message_3 = {{ $commitmentFixtures.bls12-381-sha-256.commit002.committedMessages[2] }}
committed_message_4 = {{ $commitmentFixtures.bls12-381-sha-256.commit002.committedMessages[3] }}
committed_message_5 = {{ $commitmentFixtures.bls12-381-sha-256.commit002.committedMessages[4] }}

prover_blind = {{ $commitmentFixtures.bls12-381-sha-256.commit002.proverBlind }}
commitment_with_proof = {{ $commitmentFixtures.bls12-381-sha-256.commit002.commitmentWithProof }}
```

### Signature

#### No Committed Messages, No Signer Messages

```
Mocked RNG parameters for commitment:
    dst = {{ $signatureFixtures.bls12-381-sha-256.signature001.mockRngParameters.commit.DST }}
    count =  {{ $signatureFixtures.bls12-381-sha-256.signature001.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-sha-256.signature001.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-sha-256.signature001.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-sha-256.signature001.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-sha-256.signature001.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-sha-256.signature001.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-sha-256.signature001.header }}

messages = {{ $signatureFixtures.bls12-381-sha-256.signature001.messages }}

committed_messages = {{ $signatureFixtures.bls12-381-sha-256.signature001.committedMessages }}

prover_blind = {{ $signatureFixtures.bls12-381-sha-256.signature001.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-sha-256.signature001.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-sha-256.signature001.signature }}
```

#### Multiple Prover Committed Messages, No Signer Messages

```
Mocked RNG parameters for commitment:
    dst = {{ $signatureFixtures.bls12-381-sha-256.signature002.mockRngParameters.commit.DST }}
    count =  {{ $signatureFixtures.bls12-381-sha-256.signature002.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-sha-256.signature002.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-sha-256.signature002.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-sha-256.signature002.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-sha-256.signature002.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-sha-256.signature002.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-sha-256.signature002.header }}

messages = {{ $signatureFixtures.bls12-381-sha-256.signature002.messages }}

committed_message_1 = {{ $signatureFixtures.bls12-381-sha-256.signature002.committedMessages[0] }}
committed_message_2 = {{ $signatureFixtures.bls12-381-sha-256.signature002.committedMessages[1] }}
committed_message_3 = {{ $signatureFixtures.bls12-381-sha-256.signature002.committedMessages[2] }}
committed_message_4 = {{ $signatureFixtures.bls12-381-sha-256.signature002.committedMessages[3] }}
committed_message_5 = {{ $signatureFixtures.bls12-381-sha-256.signature002.committedMessages[4] }}

prover_blind = {{ $signatureFixtures.bls12-381-sha-256.signature002.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-sha-256.signature002.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-sha-256.signature002.signature }}
```

#### No Prover Committed Messages, Multiple Signer Messages

```
Mocked RNG parameters for commitment:
    dst = {{ $signatureFixtures.bls12-381-sha-256.signature003.mockRngParameters.commit.DST }}
    count =  {{ $signatureFixtures.bls12-381-sha-256.signature003.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-sha-256.signature003.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-sha-256.signature003.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-sha-256.signature003.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-sha-256.signature003.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-sha-256.signature003.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-sha-256.signature003.header }}

messages_1 = {{ $signatureFixtures.bls12-381-sha-256.signature003.messages[0] }}
messages_2 = {{ $signatureFixtures.bls12-381-sha-256.signature003.messages[1] }}
messages_3 = {{ $signatureFixtures.bls12-381-sha-256.signature003.messages[2] }}
messages_4 = {{ $signatureFixtures.bls12-381-sha-256.signature003.messages[3] }}
messages_5 = {{ $signatureFixtures.bls12-381-sha-256.signature003.messages[4] }}
messages_6 = {{ $signatureFixtures.bls12-381-sha-256.signature003.messages[5] }}
messages_7 = {{ $signatureFixtures.bls12-381-sha-256.signature003.messages[6] }}
messages_8 = {{ $signatureFixtures.bls12-381-sha-256.signature003.messages[7] }}
messages_9 = {{ $signatureFixtures.bls12-381-sha-256.signature003.messages[8] }}
messages_10 = {{ $signatureFixtures.bls12-381-sha-256.signature003.messages[9] }}

committed_message = {{ $signatureFixtures.bls12-381-sha-256.signature003.committedMessages }}

prover_blind = {{ $signatureFixtures.bls12-381-sha-256.signature003.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-sha-256.signature003.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-sha-256.signature003.signature }}
```

#### Multiple Prover Committed and Signer Messages

```
Mocked RNG parameters for commitment:
    dst = {{ $signatureFixtures.bls12-381-sha-256.signature004.mockRngParameters.commit.DST }}
    count =  {{ $signatureFixtures.bls12-381-sha-256.signature004.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-sha-256.signature004.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-sha-256.signature004.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-sha-256.signature004.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-sha-256.signature004.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-sha-256.signature004.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-sha-256.signature004.header }}

messages_1 = {{ $signatureFixtures.bls12-381-sha-256.signature004.messages[0] }}
messages_2 = {{ $signatureFixtures.bls12-381-sha-256.signature004.messages[1] }}
messages_3 = {{ $signatureFixtures.bls12-381-sha-256.signature004.messages[2] }}
messages_4 = {{ $signatureFixtures.bls12-381-sha-256.signature004.messages[3] }}
messages_5 = {{ $signatureFixtures.bls12-381-sha-256.signature004.messages[4] }}
messages_6 = {{ $signatureFixtures.bls12-381-sha-256.signature004.messages[5] }}
messages_7 = {{ $signatureFixtures.bls12-381-sha-256.signature004.messages[6] }}
messages_8 = {{ $signatureFixtures.bls12-381-sha-256.signature004.messages[7] }}
messages_9 = {{ $signatureFixtures.bls12-381-sha-256.signature004.messages[8] }}
messages_10 = {{ $signatureFixtures.bls12-381-sha-256.signature004.messages[9] }}

committed_message_1 = {{ $signatureFixtures.bls12-381-sha-256.signature004.committedMessages[0] }}
committed_message_2 = {{ $signatureFixtures.bls12-381-sha-256.signature004.committedMessages[1] }}
committed_message_3 = {{ $signatureFixtures.bls12-381-sha-256.signature004.committedMessages[2] }}
committed_message_4 = {{ $signatureFixtures.bls12-381-sha-256.signature004.committedMessages[3] }}
committed_message_5 = {{ $signatureFixtures.bls12-381-sha-256.signature004.committedMessages[4] }}

prover_blind = {{ $signatureFixtures.bls12-381-sha-256.signature004.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-sha-256.signature004.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-sha-256.signature004.signature }}
```

#### Multiple Prover Committed and Signer Messages, No Signer Blind

```
Mocked RNG parameters for commitment:
    dst = {{ $signatureFixtures.bls12-381-sha-256.signature005.mockRngParameters.commit.DST }}
    count =  {{ $signatureFixtures.bls12-381-sha-256.signature005.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-sha-256.signature005.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-sha-256.signature005.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-sha-256.signature005.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-sha-256.signature005.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-sha-256.signature005.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-sha-256.signature005.header }}

messages_1 = {{ $signatureFixtures.bls12-381-sha-256.signature005.messages[0] }}
messages_2 = {{ $signatureFixtures.bls12-381-sha-256.signature005.messages[1] }}
messages_3 = {{ $signatureFixtures.bls12-381-sha-256.signature005.messages[2] }}
messages_4 = {{ $signatureFixtures.bls12-381-sha-256.signature005.messages[3] }}
messages_5 = {{ $signatureFixtures.bls12-381-sha-256.signature005.messages[4] }}
messages_6 = {{ $signatureFixtures.bls12-381-sha-256.signature005.messages[5] }}
messages_7 = {{ $signatureFixtures.bls12-381-sha-256.signature005.messages[6] }}
messages_8 = {{ $signatureFixtures.bls12-381-sha-256.signature005.messages[7] }}
messages_9 = {{ $signatureFixtures.bls12-381-sha-256.signature005.messages[8] }}
messages_10 = {{ $signatureFixtures.bls12-381-sha-256.signature005.messages[9] }}

committed_message_1 = {{ $signatureFixtures.bls12-381-sha-256.signature005.committedMessages[0] }}
committed_message_2 = {{ $signatureFixtures.bls12-381-sha-256.signature005.committedMessages[1] }}
committed_message_3 = {{ $signatureFixtures.bls12-381-sha-256.signature005.committedMessages[2] }}
committed_message_4 = {{ $signatureFixtures.bls12-381-sha-256.signature005.committedMessages[3] }}
committed_message_5 = {{ $signatureFixtures.bls12-381-sha-256.signature005.committedMessages[4] }}

prover_blind = {{ $signatureFixtures.bls12-381-sha-256.signature005.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-sha-256.signature005.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-sha-256.signature005.signature }}
```

#### No Commitment Signature

```
Mocked RNG parameters for the signature:
    dst = {{ $signatureFixtures.bls12-381-sha-256.signature006.mockRngParameters.signature.DST }}
    count =  {{ $signatureFixtures.bls12-381-sha-256.signature006.mockRngParameters.signature.count }}

SK = {{ $signatureFixtures.bls12-381-sha-256.signature006.signerKeyPair.secretKey }}
PK = {{ $signatureFixtures.bls12-381-sha-256.signature006.signerKeyPair.publicKey }}

commitment_with_proof = {{ $signatureFixtures.bls12-381-sha-256.signature006.commitmentWithProof }}
header = {{ $signatureFixtures.bls12-381-sha-256.signature006.header }}

messages_1 = {{ $signatureFixtures.bls12-381-sha-256.signature006.messages[0] }}
messages_2 = {{ $signatureFixtures.bls12-381-sha-256.signature006.messages[1] }}
messages_3 = {{ $signatureFixtures.bls12-381-sha-256.signature006.messages[2] }}
messages_4 = {{ $signatureFixtures.bls12-381-sha-256.signature006.messages[3] }}
messages_5 = {{ $signatureFixtures.bls12-381-sha-256.signature006.messages[4] }}
messages_6 = {{ $signatureFixtures.bls12-381-sha-256.signature006.messages[5] }}
messages_7 = {{ $signatureFixtures.bls12-381-sha-256.signature006.messages[6] }}
messages_8 = {{ $signatureFixtures.bls12-381-sha-256.signature006.messages[7] }}
messages_9 = {{ $signatureFixtures.bls12-381-sha-256.signature006.messages[8] }}
messages_10 = {{ $signatureFixtures.bls12-381-sha-256.signature006.messages[9] }}

committed_message = {{ $signatureFixtures.bls12-381-sha-256.signature006.committedMessages }}

prover_blind = {{ $signatureFixtures.bls12-381-sha-256.signature006.proverBlind }}
signer_blind = {{ $signatureFixtures.bls12-381-sha-256.signature006.signerBlind }}

signature = {{ $signatureFixtures.bls12-381-sha-256.signature006.signature }}
```

### Proof

#### All Prover Committed Messages and Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof001.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof001.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof001.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof001.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof001.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof001.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-sha-256.proof001.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-sha-256.proof001.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof001.signature }}

header = {{ $proofFixtures.bls12-381-sha-256.proof001.header }}
ph = {{ $proofFixtures.bls12-381-sha-256.proof001.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-sha-256.proof001.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-sha-256.proof001.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof001.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-sha-256.proof001.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-sha-256.proof001.disclosedData }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof001.proof }}
```

#### Half Prover Committed Messages and All Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof002.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof002.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof002.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof002.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof002.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof002.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-sha-256.proof002.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-sha-256.proof002.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof002.signature }}

header = {{ $proofFixtures.bls12-381-sha-256.proof002.header }}
ph = {{ $proofFixtures.bls12-381-sha-256.proof002.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-sha-256.proof002.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-sha-256.proof002.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof002.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-sha-256.proof002.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-sha-256.proof002.disclosedData }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof002.proof }}
```

#### All Prover Committed Messages and Half Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof003.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof003.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof003.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof003.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof003.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof003.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-sha-256.proof003.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-sha-256.proof003.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof003.signature }}

header = {{ $proofFixtures.bls12-381-sha-256.proof003.header }}
ph = {{ $proofFixtures.bls12-381-sha-256.proof003.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-sha-256.proof003.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-sha-256.proof003.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof003.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-sha-256.proof003.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-sha-256.proof003.disclosedData }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof003.proof }}
```

#### Half Prover Committed Messages and Half Signer Messages

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof004.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof004.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof004.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof004.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof004.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof004.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-sha-256.proof004.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-sha-256.proof004.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof004.signature }}

header = {{ $proofFixtures.bls12-381-sha-256.proof004.header }}
ph = {{ $proofFixtures.bls12-381-sha-256.proof004.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-sha-256.proof004.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-sha-256.proof004.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof004.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-sha-256.proof004.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-sha-256.proof004.disclosedData }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof004.proof }}
```

#### No Prover Committed Messages and Half Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof005.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof005.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof005.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof005.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof005.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof005.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-sha-256.proof005.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-sha-256.proof005.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof005.signature }}

header = {{ $proofFixtures.bls12-381-sha-256.proof005.header }}
ph = {{ $proofFixtures.bls12-381-sha-256.proof005.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-sha-256.proof005.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-sha-256.proof005.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof005.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-sha-256.proof005.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-sha-256.proof005.disclosedData }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof005.proof }}
```

#### Half Prover Committed Messages and No Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof006.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof006.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof006.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof006.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof006.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof006.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-sha-256.proof006.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-sha-256.proof006.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof006.signature }}

header = {{ $proofFixtures.bls12-381-sha-256.proof006.header }}
ph = {{ $proofFixtures.bls12-381-sha-256.proof006.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-sha-256.proof006.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-sha-256.proof006.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof006.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-sha-256.proof006.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-sha-256.proof006.disclosedData }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof006.proof }}
```

#### No Prover Committed Messages and No Signer Messages Disclosed

```
Mocked RNG parameters for commitment:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof007.mockRngParameters.commit.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof007.mockRngParameters.commit.count }}

Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof007.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof007.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof007.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof007.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-sha-256.proof007.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-sha-256.proof007.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof007.signature }}

header = {{ $proofFixtures.bls12-381-sha-256.proof007.header }}
ph = {{ $proofFixtures.bls12-381-sha-256.proof007.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-sha-256.proof007.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-sha-256.proof007.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof007.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-sha-256.proof007.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-sha-256.proof007.disclosedData }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof007.proof }}
```

#### No Commitment and Half Signer Messages Disclosed

```
Mocked RNG parameters for the signature:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof008.mockRngParameters.signature.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof008.mockRngParameters.signature.count }}

Mocked RNG parameters for the proof:
    dst = {{ $proofFixtures.bls12-381-sha-256.proof008.mockRngParameters.proof.DST }}
    count =  {{ $proofFixtures.bls12-381-sha-256.proof008.mockRngParameters.proof.count }}

message_1 = {{ $messages.messages[0] }}
message_2 = {{ $messages.messages[1] }}
message_3 = {{ $messages.messages[2] }}
message_4 = {{ $messages.messages[3] }}
message_5 = {{ $messages.messages[4] }}
message_6 = {{ $messages.messages[5] }}
message_7 = {{ $messages.messages[6] }}
message_8 = {{ $messages.messages[7] }}
message_9 = {{ $messages.messages[8] }}
message_10 = {{ $messages.messages[9] }}

committed_message_1 = {{ $messages.committedMessages[0] }}
committed_message_2 = {{ $messages.committedMessages[1] }}
committed_message_3 = {{ $messages.committedMessages[2] }}
committed_message_4 = {{ $messages.committedMessages[3] }}
committed_message_5 = {{ $messages.committedMessages[4] }}

commitment_with_proof = {{ $proofFixtures.bls12-381-sha-256.proof008.commitmentWithProof }}

PK = {{ $proofFixtures.bls12-381-sha-256.proof008.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof008.signature }}

header = {{ $proofFixtures.bls12-381-sha-256.proof008.header }}
ph = {{ $proofFixtures.bls12-381-sha-256.proof008.presentationHeader }}

disclosed_indexes = {{ $proofFixtures.bls12-381-sha-256.proof008.revealedMessages }}
disclosed_commitment_indexes = {{ $proofFixtures.bls12-381-sha-256.proof008.revealedCommittedMessages }}

proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof008.proverBlind }}
signerBlind = {{ $proofFixtures.bls12-381-sha-256.proof008.signerBlind }}

(disclosed_msgs, disclosed_idxs) = {{ $proofFixtures.bls12-381-sha-256.proof008.disclosedData }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof008.proof }}
```


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
