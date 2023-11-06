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
: A Pedersen commitment ([@P91]) constructed over a vector of messages, as described e.g., in [@BG18].

committed\_messages
: A list of messages committed by the Prover to a commitment.

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


# Scheme Definition

## Commitment Operations

### Commitment Computation

This operation is used by the Prover to create `commitment` to a set of messages (`committed_messages`), that they intent to include to the signature. Note that this operation returns both the serialized commitment as well as the random scalar used to blind it (`prover_blind`).

This operation uses the the `get_random_scalars` operation defined in [TODO].

```
commitment = Commit(committed_messages)

Inputs:

- committed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied it defaults to the empty
                                 array "()".

Outputs:

- blind_result, a vector comprising from an octet string and a random
                scalar in that order.

Procedure:

1.  generators = create_generators(M + 2, api_id)
2.  (Q_2, J_1, ..., J_M) = generators[1..M+1]

2.  (msg_1, ..., msg_M) = messages_to_scalars(committed_messages)
3.  (prover_blind, s~, m~_1, ..., m~_M) = get_random_scalars(M + 2)

4.  C = Q_2 * prover_blind + J_1 * msg_1 + ... + J_M * msg_M
5.  Cbar = Q_2 * s~ + J_1 * m~_1 + ... + J_M * m~_M

6.  challenge = calculate_blind_challenge(C, Cbar, M, generators)

7.  s^ = s~ + prover_blind * challenge
8.  for m in (1, 2, ..., M): m^_i = m~_1 + msg_i * challenge
9.  proof = (s^, (m^_1, ..., m^_M), challenge)
10. commitment_octs = commitment_to_octets(C, proof)
10. return (commitment_octs, prover_blind)
```

### Commitment Verification

This operation is used by the Signer to verify the correctness of a supplied `commitment`, over a list of points of G1 called the `blind_generators`.

```
res = verify_commitment(commitment, blind_generators)

Inputs:

- commitment (REQUIRED), a vector comprising from a point of G1 and
                         another vector containing a scalars, a possibly
                         empty set of scalars and another scalar, in
                         that order.
- blind_generators (REQUIRED), vector of pseudo-random points in G1.

Deserialization:

1. (Com, proof) = commitment_result
2. (s^, commitments, cp) = proof

3. M = length(commitments)
4. (m^_1, ..., m^_M) = commitments

5. if length(blind_generators) != M + 1, return INVALID
6. (Q_2, J_1, ..., J_M) = blind_generators

Procedure:

1. Cbar = Q_2 * s^ + J_1 * m^_1 + ... + J_M * m^_M + Com * (-cp)
2. cv = calculate_blind_challenge(Com, Cbar, M, blind_generators)
3. if cv != cp, return INVALID
4. return VALID
```

## Blind BBS Signatures Interface

### Blind Signature Generation

This operation returns a BBS blind signature from a secret key (SK), over a header, a set of messages and optionally a commitment value, as outputted by the `Commit` operation ((#commitment-computation)). The issuer can also further randomize the supplied commitment, by supplying a random scalar (`signer_blind`), that MUST be computed as,

```
signer_blind = get_random_scalars(1)
```

If the `signer_blind` input is not supplied, it will default to the zero scalar (`0`).

```
blind_signature = BlindSign(SK, PK, commitment, header, messages,
                                                           signer_blind)

Inputs:

- SK (REQUIRED), a secret key in the form outputted by the KeyGen
                 operation.
- PK (REQUIRED), an octet string of the form outputted by SkToPk
                 provided the above SK as input.
- commitment (OPTIONAL), an octet string. If not supplied, it defaults
                         to the empty string ("").
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


Deserialization:

1. com_len_floor = point_octet_length + 2 * scalar_octet_length
2. commits_len = 0
3. if commitment != "", commits_len = length(commitment) - com_len_floor
4. M = floor(commits_len / octet_scalar_length)
5. L = length(messages)

Procedure:

1. all_generators = create_generators(M + L + 2, api_id)
2. generators = all_generators[0]
3. blind_generators = all_generators[1]
4. blind_generators.append(all_generators[2..M])
5. generators.append(all_generators(M + 2..M + L + 2))

5. message_scalars = messages_to_scalars(messages)

6. blind_sig = CoreBlindSign(SK,
                             PK,
                             commitment,
                             generators,
                             blind_generators,
                             header,
                             messages,
                             signer_blind,
                             api_id)
7. if blind_sig is INVALID, return INVALID
8. return blind_sig
```

### Blind Signature Verification

This operation validates a blind BBS signature (`signature`), given the Signer's public key (`PK`), a header (`header`), a set of known to the Signer messages (`messages`) and if used, a set of committed messages (`committed_messages`), the `prover_blind` as returned by the `Commit` operation ((#commitment-computation)) and a blind factor supplied by the Signer (`signer_blind`).

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

Procedure:

1. message_scalars = (prover_blind + signer_blind)
2. message_scalars.append(messages_to_scalars(
                                       committed_messages, api_id))
3. message_scalars.append(messages_to_scalars(messages, api_id))

4. generators = create_generators(L + M + 2, api_id)
5. res = BBS.CoreVerify(PK, signature, generators, header, messages,
                                                                 api_id)
6. return res
```

### Proof Generation

This operation creates a BBS proof, which is a zero-knowledge, proof-of-knowledge, of a BBS signature, while optionally disclosing any subset of the signed messages. Note that in contrast to the `ProofGen` operation of [@!I-D.irtf-cfrg-bbs-signatures] (see [Section 3.5.3](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-generation-proofgen)), the `ProofGen` operation defined in this section accepts 2 different lists of messages and disclosed indexes, one for the messages known to the Signer (`messages`) and teh corresponding disclosed indexes (`disclosed_indexes`) and one for the messages committed by the Prover (`committed_messages`) and the corresponding disclosed indexes (`disclosed_commitment_indexes`).

To Verify a proof however, the Verifier expects only one list of messages and one list of disclosed indexes (see (#proof-verification)). This is done to not reveal to the proof Verifier which of the disclosed messages where committed by the Prover and which are known to the Verifier. See (#present-and-verify-a-bbs-proof) on how the Prover should combine the disclosed messages and the disclosed indexes in order to present them to the Verifier.

Lastly, the the operation also expects the `prover_blind` (as returned from the `Commit` operation defined in (#commitment-computation)) and `signer_blind` (as inputted in the `BlindSign` operation defined in (#blind-signature-generation)) values. If the BBS signature is generated using a commitment value, then the `prover_blind` returned by the `Commit` operation used to generate the commitment should be provided to the `ProofGen` operation (otherwise the resulting proof will be invalid).

```
proof = ProofGen(PK,
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

- proof, an octet string; or INVALID.

Deserialization:

1. L = length(messages)
2. M = length(committed_messages)
3. if length(disclosed_indexes) > L, return INVALID
4. for i in disclosed_indexes, if i < 0 or i >= L, return INVALID
5. if length(disclosed_commitment_indexes) > M, return INVALID
6. for j in disclosed_commitment_indexes,
                               if i < 0 or i >= L, return INVALID

Procedure:

1. message_scalars = (prover_blind + signer_blind)
2. message_scalars.append(messages_to_scalars(
                                   committed_messages, api_id))
3. message_scalars.append(messages_to_scalars(messages, api_id))

4. generators = create_generators(L + M + 2, api_id)

5. indexes = ()
7. for i in disclosed_commitment_indexes: indexes.append(i + 1)
6. for j in disclosed_indexes: indexes.append(M + j + 1)

8. proof = BBS.CoreProofGen(PK, signature, generators, header, ph,
                                       message_scalars, indexes, api_id)
9. return proof
```

### Proof Verification

The proof verification operation for blind signatures works exactly as the `ProofVerify` operation defined in [Section 3.5.4](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-verification-proofver) of [@!I-D.irtf-cfrg-bbs-signatures], instantiated with the following parameter

```
api_id = ciphersuite_id || "BLIND_H2G_HM2S_", where ciphersuite_id is
         defined by the ciphersuite and "BLIND_H2G_HM2S_"is an ASCII
         string comprised of 15 bytes.
```

Note that the Prover should follow the procedure described in (#present-and-verify-a-bbs-proof) to prepare the data that will be supplied to the proof Verifier.

## Core Operations

### Core Blind Sign

This operation computes a blind BBS signature, from a secret key (`SK`) over a supplied commitment (`commitment`), a header (`header`) and a set of messages (`messages`).

```
blind_signature = CoreBlindSign(SK,
                                PK,
                                commitment,
                                generators,
                                blind_generators,
                                header,
                                messages,
                                signer_blind,
                                api_id)

Inputs:

- SK (REQUIRED), a secret key in the form outputted by the KeyGen
                 operation.
- PK (REQUIRED), an octet string of the form outputted by SkToPk
                 provided the above SK as input.
- commitment (REQUIRED), an octet string of the form outputted by the
                         Blind operation.
- generators (REQUIRED), vector of pseudo-random points in G1.
- blind_generators (REQUIRED), vector of pseudo-random points in G1.
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


Deserialization:

1. L = length(messages)
2. (msg_1, ... ,msg_L) = messages

3. if length(generators) != L + 1, return INVALID
4. (Q_1, H_1, ..., H_L) = generators

5. M = length(blind_generators) - 1
6. if M < 0, return INVALID
7. all_generators = (generators[0],
                     blind_generators[0],
                     blind_generators[1..M],
                     generators[1..L])

Procedure:

// Verify the commitment's proof of correctness
1.  commitment_res = commitment_validate_and_deserialize(commitment,
                                                       blind_generators)
2.  if commitment_res is INVALID, return INVALID
// if commitment == "", then commitment_res = (Identity_G1, ())
3.  (Com, _) = commitment_res

// Blind Sign
4.  domain = calculate_domain(PK, all_generators, header, api_id)

5.  e_octs = serialize((SK, domain, msg_1, ..., msg_L, signer_blind))
6.  e = hash_to_scalar(e_octs || commitment, signature_dst)

7.  Com = Com + Q_2 * signer_blind
8.  B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L + Com
9.  A = B * (1 / (SK + e))
10. return signature_to_octets((A, e))

11. return signature
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
4. for i in disclosed_indexes: indexes.append(i + 1)
5. for j in disclosed_commitment_indexes: indexes.append(L + j + 1)

// combine the revealed messages
6. disclosed_messages = (messages[i1], ..., messages[iL])
7. disclosed_committed_messages = (committed_messages[j1], ...
                                            ..., committed_messages[jM])
8. disclosed_messages.append(disclosed_committed_messages)

9. return(disclosed_messages, indexes)
```

# Utilities

## Blind Challenge Calculation

```
challenge = calculate_blind_challenge(C, Cbar, generators)

Inputs:

- C (REQUIRED), a point of G1.
- Cbar (REQUIRED), a point of G1.
- generators (REQUIRED), an array of points from G1, of length at
                         least 1.

Parameters:

- blind_challenge_dst, an octet string representing the domain
                       separation tag: ciphersuite_id || "H2S_" where
                       ciphersuite_id is defined by the ciphersuite and
                       "H2S_" is an ASCII string comprised of 4 bytes.

Deserialization:

1. Q_2 = generators[0]
2. J_Points = ()
3. M = length(generators) - 1
4. if M > 0, J_Points = generators[1..M]

Procedure:

1. c_arr = (C, Cbar, M, Q_2)
2. if M > 0, c_arr.append(J_Points)
3. c_arr.append(api_id)
4. c_octs = serialize(c_arr)
5. return hash_to_scalar(c_octs, blind_challenge_dst)
```

##  Commitment Validation and Deserialization

The following is a helper operation used by the `CoreBlindSign` procedure ((#core-blind-sign)) to de-serialize and then validate a supplied commitment. Note that the `commitment` input to `CoreBlindSign` is optional. If a `commitment` is not supplied, the following operation will return the `Identity_G1` as the commitment point, which will be ignored by all computations during `CoreBlindSign`.

```
res = commitment_validate_and_deserialize(commitment, blind_generators)

Inputs:

- commitment (OPTIONAL), octet string. If it is not supplied it defaults
                         to the empty octet string ("").
- blind_generators (OPTIONAL), vector of points of G1. If it is not
                               supplied it defaults to the empty set
                               ("()").

Outputs:

- res, a vector comprising from a point of G1 and another vector
       containing a scalars, a possibly empty set of scalars and another
       scalar, in that order, or INVALID.

Procedure:

1. if commitment is the empty string (""), return (Identity_G1, ())
2. com_res = commitment_to_octets(commitment)
3. if com_res is INVALID, return INVALID
5. validation_res = verify_commitment(com_res, blind_generators)
6. if validation_res is INVALID, return INVALID
7. return com_res
```

## Serialize

### Commitment to Octets

```
commitment_octets = commitment_to_octets(commitment, proof)

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

### Octet to Commitment

```
commitment = octets_to_commitment(commitment_octs)

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

1.  C_octets = commitment_octs[0..(octet_point_length - 1)]
2.  C = octets_to_point_g1(C_octets)
3.  if C is INVALID, return INVALID
4.  if C == Identity_G1, return INVALID

5.  j = 0
6.  index = octet_point_length
7.  while index < length(commitment_octs):
8.      end_index = index + octet_scalar_length - 1
9.      s_j = OS2IP(proof_octets[index..end_index])
10.     if s_j = 0 or if s_j >= r, return INVALID
11.     index += octet_scalar_length
12.     j += 1

13. if index != length(commitment_octs), return INVALID
14. if j < 2, return INVALID
15. msg_commitment = ()
16. if j >= 3, set msg_commitment = (s_2, ..., s_(j-1))
17. return (C, (s_0, msg_commitments, s_j))
```

# Security Considerations

// TODO

# Ciphersuites

// TODO

# IANA Considerations

This document does not make any requests of IANA.

{backmatter}

# Appendix

## Test Vectors

// TODO

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
