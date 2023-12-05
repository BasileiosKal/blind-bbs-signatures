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

messages_1 = {{ $messages.messages[0] }}
messages_2 = {{ $messages.messages[1] }}
messages_3 = {{ $messages.messages[2] }}
messages_4 = {{ $messages.messages[3] }}
messages_5 = {{ $messages.messages[4] }}
messages_6 = {{ $messages.messages[5] }}
messages_7 = {{ $messages.messages[6] }}
messages_8 = {{ $messages.messages[7] }}
messages_9 = {{ $messages.messages[8] }}
messages_10 = {{ $messages.messages[9] }}

committed_messages_1 = {{ $messages.committedMessages[0] }}
committed_messages_2 = {{ $messages.committedMessages[1] }}
committed_messages_3 = {{ $messages.committedMessages[2] }}
committed_messages_4 = {{ $messages.committedMessages[3] }}
committed_messages_5 = {{ $messages.committedMessages[4] }}

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