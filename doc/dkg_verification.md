# Zero-Knowledge Verification of Distributed Key Generation

## 1. Introduction

### Purpose and Scope

This specification provides a detailed framework for zero-knowledge (ZK) verification circuits within a Distributed Key Generation (DKG) protocol. It emphasizes precise cryptographic formulations to ensure the correctness and security of each verification step.

### Overview of Distributed Key Generation (DKG)

DKG enables a set of \(n\) participants to collaboratively generate a shared public key without any single party knowing the corresponding private key. This is achieved through:

- **Shamir's Secret Sharing**: Distributes a secret among participants such that any subset of \(t+1\) can reconstruct it, but no subset of \(t\) or fewer can.
- **Verifiable Secret Sharing (VSS)**: Enhances Shamir's scheme by allowing participants to verify the correctness of their received shares.
- **Zero-Knowledge Proofs (ZKPs)**: Allow participants to prove the validity of their actions without revealing any secret information.

The protocol outputs:
  - Each participent will reconstruct partial secret \(S_i\) such that \(SS = L(S_0 \dots Sn)\) where L using largrange interpolation to calculate
  \(F(0) \text{ for polynom that } S_1 = f(1), S_2, = f(2), etc \)
  - \(SS\) is the shared secret between the participents

The protocl ensure:
- The secret was generated according to Shamir's Secret Sharing scheme.
- Any deviation—intentional or not—by participants can be detected and the malicious participent can be identified.

## 2. DKG Process Overview


### 2.0 High-Level Overview of Provable Distributed Key Generation (PDKG)

1. **Initialization (Public Setup Phase):**  
   One participant initializes the session by publishing the setup on a shared, publicly accessible platform (e.g., a blockchain smart contract, shared database, or bulletin board).  
   The setup includes:
   - **`N`**: Total number of participants  
   - **`K`**: Threshold number of participants required to reconstruct the secret  
   - **`sessionId`**: A unique identifier for this specific key generation session  

2. **Polynomial Generation (Secret Sharing Phase):**  
   Each participant independently generates a random polynomial of degree `K - 1`, as per Shamir's Secret Sharing.

3. **Commitment Broadcast:**  
   Each participant computes cryptographic commitments to their polynomial coefficients and the setup.
   These commitments are published to the public board to enable verifiable consistency checks.

4. **Share Distribution:**  
   Participants privately send encrypted shares (i.e., evaluations of their polynomial), along with any additional data required to prove correctness — such as the verification vector — to each of the other participants.  
   A dispute mechanism is often included to handle missing or invalid shares via public challenges. (shares can be posted publicly in encrypted)

5. **Verification and Acknowledgment:**  
   Upon receiving shares from others, each participant:  
   - Verifies the correctness of each received share against the sender's public commitment, the session setup, and the corresponding verification vector.  
   - If a share is invalid or inconsistent:
     - Constructs and publishes a proof of misbehavior (e.g., using cryptographic evidence) on the public board.  
   - If misbehavior cannot be proven or if a participant refuses to participate:
     - Posts a challenge on the public board to trigger the dispute resolution mechanism.

7. **Finalization and Proof Construction:**  
   Once enough valid shares and acknowledgments have been collected, any participant can construct a publicly verifiable proof that:
   - All distributed shares are consistent with the published commitments  
   - The collective secret can be reconstructed from the valid shares  

   If a participant misbehaves — for example, by submitting an invalid proof (e.g., a signature that doesn't correspond to their expected public key):
   - A proof of misbehavior can be constructed and published  

   If a participant refuses to cooperate (e.g., by failing to submit their signature):
   - A challenge can be posted on the public board to trigger the dispute resolution mechanism

   This ensures the key was generated honestly and can be used securely in threshold cryptographic schemes.


### 2.1 Initialization

Participants agree on:

- Threshold \(t\), total number of participants \(n\), message \(M\)
- A unique  \(\text{generation\_id}\) 
- Authentication key \(\text{AuthKey}_i\) and corresponding public key \(\text{AuthPK}_i\) for each participant \(P_i\)
- A homomorphic function \(\text{PK}(x)\), satisfying \(\text{PK}(x + y) = \text{PK}(x) + \text{PK}(y)\). For example, \(\text{PK}(x) = g \cdot x\) in BLS12-381

### 2.2 Commitment Phase

Each participant \(P_i\) samples a random polynomial:
\[f_i(x) = a_{i,0} + a_{i,1}x + \dots + a_{i,t}x^t\]

Where:

- \(a_{i,j} \in \mathbb{F}_q\): Random coefficients
- \(f_i(x)\): Secret polynomial of \(P_i\)

We define a verification vector \(\text{V}_i\) as:
\[(\text{PK}(a_{i,0}), \dots, \text{PK}(a_{i,t}))\]

The secret share is \(s_i = f_i(0)\).

Commitment:
\[C_i = \text{HASH}(k, n, \text{generation\_id}, \text{V}_i)\]

Published to a public board and signed with \(\text{AuthKey}_i\).

### 2.3 Share Distribution

Each \(P_i\) computes:
\[s_{i,j} = f_i(j)\]

Sends to \(P_j\) along with \(\text{V}_i\), all signed with \(\text{AuthKey}_i\).

### 2.4 Share Verification

Upon receiving \(s_{i,j}\) and \(\text{V}_i\), participant \(P_j\) performs the following verifications:

- **Hash Consistency**:
  \[
  C_i = \text{HASH}(k, n, \text{generation\_id}, \text{V}_i)
  \]

- **Polynomial Evaluation**:

  Define the verification polynomial:
  \[
  p_i(x) = \sum_{j=0}^t \text{PK}(a_{i,j}) \cdot x^j, \quad \text{where } \text{PK}(a_{i,j}) \in \text{V}_i
  \]

  Then verify:
  \[
  \text{PK}(s_{i,j}) = p_i(j)
  \]

If a participant submits a share that cannot be verified or if there is insufficient evidence to validate its correctness, and malicious intent is suspected, then participant \(P_j\) should initiate a **challenge** against \(P_i\) on the public board.

The challenge must include an expiration timestamp. The response to the challenge should be **encrypted using ECDH** (Elliptic Curve Diffie-Hellman) with the `AuthKey`s of both participants.

If the challenge expires without a valid response, or if the response is invalid, the protocol can demonstrate misbehavior by \(P_i\), which may result in penalties (e.g., slashing). If the protocol fails, all participants can verify the failure based on the data recorded on the public board.

The use of encryption and zero-knowledge proofs guarantees that sensitive information is never exposed on the public board at any stage of the protocol.

### 2.5 Partial Key Generation

Each \(P_i\) computes:
\[S_i = \sum_{k=0}^{n} s_{k,i}\]

Where \(s_{k,i}\) is the share from \(P_k\) to \(P_i\).


### 2.6 Finalization

During the final round, each participant \(P_i\) broadcasts a signature over message \(SM_i\) to all other participants.

Given that each participant possesses the verification vectors of all others, they can independently verify that each \(SM_i\) is signed using the correct partial secret key associated with \(P_i\).

If an invalid signature is detected, it constitutes cryptographic proof of misbehavior. However, if a participant withholds participation or provides malformed data that cannot be conclusively proven malicious, a fallback challenge mechanism is triggered. At this stage, since no private information is exchanged, both the challenge and response may occur without encryption.

Once all valid signatures are collected, any participant (or a subset thereof) can construct a final proof that the secret sharing protocol has completed successfully, and that the reconstructed shared secret is \(SS\). This proof is published to the public board, finalizing the protocol execution.



## 3. Verification Circuit Analysis

### Circuit 1: Incorrect Share Detection

- **Objective**: Determine whether the share \(s_{i,j}\) is invalid, either due to incorrect polynomial evaluation or inconsistent public commitments.

- **Verification Process**:
  1. **Commitment Hash Check**:  
     Confirm that the provided commitment hash \(C_i\) matches the expected hash derived from \((k, n, \text{generation\_id}, V_i)\).  
     If the hash does not match and the discrepancy cannot be proven, initiate the fallback challenge mechanism.

  2. **Signature Authentication**:  
     Verify the authenticity of \(C_i\) using the public authentication key \(\text{AuthPK}_i\).  
     If the signature is invalid and lacks cryptographic proof of misbehavior, fall back to the challenge protocol.

  3. **Share Evaluation**:  
     Evaluate whether:
     \[
     \text{PK}(s_{i,j}) \stackrel{?}{=} \sum_{k=0}^t \text{PK}(a_{i,k}) \cdot j^k
     \]
     A mismatch here provides verifiable evidence of an invalid share.

- **Result**:  
  The circuit succeeds if it can produce a verifiable contradiction. If no contradiction is detected and no cryptographic proof is available, the circuit defers to the challenge mechanism.


### Circuit 2: Incorrect Partial Public Key Detection

1. **Signature Verification**:  
   Verify the signature over the input data using the authentication key \(\text{AuthPK}_i\).  
   If the signature is invalid but not provably malicious, fallback to the challenge mechanism.

2. **Construct the Aggregated Polynomial**:  
   \[
   P(x) = \sum_{k=0}^t \left( \sum_{s=0}^n \text{PK}(a_{s,k}) \right) x^k, \quad \text{where } \text{PK}(a_{s,k}) \in V_s
   \]
   **Note**:  
   The public key of the aggregated secret share can be represented as:  
   \[
   \text{PK}\left( \sum_{j=0}^n s_{j,i} \right) = \sum_{j=0}^n \text{PK}(s_{j,i})
   \]

3. **Proof of Correct Reconstruction**:  
   Prove that:
   \[
   P(i) = \text{PK}(s_i) = PK_i
   \]

4. **Signature Validation**:  
   Verify that the message signature \(SM_i\) is valid using the public key \(\text{PK}(s_i)\).

- **Expected Output**:  
  Successfully generate a proof if either step (3) or (4) fails, indicating incorrect share reconstruction or invalid signature.


### Circuit 3: Malicious Encryption Detection

- **Objective**: Verify that encrypted shares decrypt correctly and correspond to valid values.

- **Verification Steps**:
  1. **Key Derivation (ECDH)**:  
     TODO: explain how to derive the key
  2. **Decryption and Share Extraction**:  
     Decrypt the ciphertext using \(K_{i,j}\) to obtain the share \(s_{i,j}\).

  3. **Share Validation**:  
     Apply the same validation logic as in **Circuit 1** to accept or reject the decrypted share.  
     This includes checking commitment consistency and verifying that the share satisfies the expected polynomial evaluation.

- **Expected Output**:  
  The circuit fails if the decrypted share is invalid or inconsistent with the public commitments.


### Circuit 4: Successful Finalization

- **Objective**: Verify the correctness of the final reconstructed key and confirm that all participants have properly completed the protocol.

- **Verification Steps**:
  1. **Commitment Validation**:  
     Prove that each commitment \(C_i\) is consistent with the corresponding verification vector \(V_i\).

  2. **Partial Key Consistency**:  
     Verify that each participant’s public key satisfies:
     \[
     PK_i = \text{P}(i), \quad \text{where } i \in [1, n]
     \]
     This ensures that each participant has correctly reconstructed their partial key from the shared polynomial.

  3. **Message Signature Validation**:  
     Prove that each signature over message \(M\) was generated using the corresponding partial secret key.

  4. **Final Key Reconstruction via Lagrange Interpolation**:  
     Use Lagrange interpolation \(L\) to reconstruct the final public key:
     \[
     L(PK_0, \dots, PK_n) = \text{PK}(SS) = \text{P}(0)
     \]

     **Note:**  
     The interpolation can be performed over any subset \(S\) satisfying:
     \[
     |S| = m, \quad \text{where } m \in [k, n], \quad \text{and} \quad S \subseteq \{PK_0, \dots, PK_n\}
     \]
     This demonstrates that any subset of at least \(k\) participants can reconstruct the shared secret.  
     However, to confirm correctness for all participants, it is recommended to use the full set of partial public keys.

- **Expected Output**:  
  The circuit succeeds only if all commitments, partial keys, signatures, and the reconstructed final key are valid.


