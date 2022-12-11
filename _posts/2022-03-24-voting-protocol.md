# Overview

This protocol will generate a signed token for each candidate. The
signature is based on the list of candidates, and the Voter’s ID, along
with two values from the Registration Authority (RA): the RA’s public
key (*PK*), and a sufficiently large prime number. To cast a vote, the
voter will send the token and signed token that correspond to their
choice of candidates. The application will count any valid (signed)
votes and reject any invalid ones.

Credit goes to the author of the Stanford article (referenced) for proposing a means to verify the votes [1]. 

## Goal

Allow the voter to send a set of (*token*, *signedtoken*) tuples to a
voting service that will verify and add their votes.

This will require generating a signed token.

That’s what the protocol is for.

## Terminology

These terms are used in the mathematics of “blind signing:”

-   The *Voter* is the person actually casting their vote.
-   The *Tabulation Authority* is whatever service or application that
    is actually counting the votes, and discarding invalid votes.
-   The *Registration Authority* (or “signing authority”) will use their
    private key to bind their identity (signature) to the voter’s own
    signed tokens.

Here’s how you could use them in a web application:

-   Voter is the client. This could be the voter’s phone, laptop, or
    even a public PC or tablet.
-   App server is the tabulation and registration authorities. For a
    small project, there is absolutely no reason why these should be
    separated.

Other terms used in the context of voting:

-   A *candidate* is any candidate, even the ones that the voter does
    not choose.
-   The *Voter ID* is the voter’s unique identifier, like the actual
    legal one for all I care.

## Data structures

-   **Token**. A representation of the candidate’s name with the Voter’s
    ID. Ideally, this is hashed for readability.
-   **Blinded token**. The token, signed by the voter
-   **Signed blind token**. The voter’s blind token, signed by the
    Registration Authority
-   **Signed token**. The unblinded signed token, which is actually the
    signature of the original token.

## Function prototypes

-   ***Hash***(**candidatename\|\|voterid**) → **token**
-   ***VoterSign***(**token**, *r*, *N*) → **blindedtoken**
-   ***RegAuthoritySign***(**blindedtoken**, *N*) → **signedblindtoken**
-   ***Unblind***(**signedblindtoken**, *r*, *N*) → **signedtoken**
-   ***Verify***(**token**, **signedtoken**) → **boolean**

## Function definitions for RSA blind signatures

***Hash*** = SHA2(*candidatename\|\|voterid*)

-   Used to create a token from the candidate’s name and voter ID. The
    token is like a fingerprint of these two values, so it preserves
    some anonymity along with data integrity.

***VoterSign*** = *token* \* *r* <sup>*PK*</sup> (mod *N*)

-   Used by the voter to sign their token with a random number and the
    RA’s public key
-   *token* : hashed candidate+voterid
-   *r* : A cryptographically secure random number
-   *PK* : The Registration Authority’s primary key
-   *N* : A sufficiently secure (large) prime number

***RegAuthoritySign*** = (*blindedtoken*)<sup>*SK*</sup> (mod *N*)

-   Used by the registration authority to sign a blindly-signed token
    from the voter
-   *blindedtoken*: The token signed by the voter
-   *SK*: The registration authority’s secret (private) key
-   *N*: The same prime number used to generate the blinded
    token

***Unblind*** = *blindedtoken* \* *r* <sup>-1</sup> (mod *N*)

-   Used by the client to get the token’s signature
-   *blindedtoken*: The token signed by the registration authority
-   *r*: The same random number used to make the original
    blind token
-   *N*: This literally has not changed

***Verify*** = (*token*<sup>SK</sup> (mod *N*) == *signedtoken*)

-   Used by the tabulation authority/server to determine is a vote is
    valid

# Protocol

Just a heads up, I’m gonna refer to the server as the registration
authority and the tabulation authority.

Likewise with “voter” and “client,” although the term client really
refers to the device, not necessarily the person.

## Signing

1.  The server generates a secret/public key (SK, PK) and a sufficiently
    large prime number, *N*.

2.  The client obtains (downloads) the server’s *PK* and *N*, along with
    a list of all candidates. The client also enters their Voter ID and generates a random number, *r*.

3.  For all candidates (even ones the client doesn’t choose), a
    client-side process creates a token by hashing the candidate’s name
    and the voter ID.

     *for each candidate*, do

     ***hash***(**candidate\|\|voterid**) → **token**

4.  Another client-side process creates a blind signature for each
    token. It does this by using the server’s private key and prime
    number.

     *for each token*, do

     ***VoterSign***(**token**, *PK*, *r*, *N*) → **blindedtoken**

5.  The client sends any authentication information, along with their
    entire list of blinded tokens, to the server.

6.  When the server receives a voter’s blinded tokens, it then proceeds
    to sign them with their secret key and the same prime number that
    was sent to and used by the client.

     *for each blinded token*, do

     ***RegAuthoritySign***(**blindedtoken**, *SK*, *N*) → **signedblindedtoken**
    
7.  The server sends the entire list of signed blinded tokens back to
    the voter.

8.  When the client receives the list of signed blinded tokens, it
    starts a process that “unblinds” each token. This reveals the
    signature for each original token.

     *for each signed blinded token*, do

     ***Unblind***(**signedblindedtoken**, *r*, *N*) → **signedtoken**

9.  Now, the user has a list of tokens, and their corresponding
    signatures. It did this without ever leaking information about the
    real token’s message (or the candidate and voter ID) to the server.
    Neat, yeah?

## Voting (verifying the signatures)

The second part of the protocol is casting the actual vote. This is
really the easiest part.

1.  Each candidate is now associated with a token, and a signed token.

2.  For each candidate that they want, the voter will select that
    candidate’s corresponding token and signed token.

3.  The client sends the (*token*, *signedtoken*) tuple to the server.

4.  Upon receiving the two-tuple, the server computes the signature of a
    token by using its secret key.

     *for each* (*token*, *signedtoken*) from a voter, do

     ***Verify***(**token**, **signedtoken**) → **valid or invalid**

5.  If it matches the value of the signed token that was sent from the
    voter, then the server knows the vote is valid, and it adds a vote
    to that candidate. Otherwise, it invalidates the message.

# Other considerations

## Receipts

At the end of the “Method 1” discussion, the Stanford article notes the
following:

> Unfortunately, receipts are needed in this scheme.

They stop just short of elaborating on what a “receipt” may look like,
along with any security or implementation considerations: for example,
if these require random values, or the point or points in the protocol
where they should occur. This is left to the reader to determine and
implement correctly.

## Security considerations

All cryptographic instances—the RA’s private key *PK*, the voter’s ID,
and the tokenizing and blind-singing algorithms—should be
cryptographically secure. Failure to do so will compromise the
confidentiality and integrity of the voting system. (A simple
proof-of-concept may reduce the robustness for these objects in order to
illustrate the merit of the protocol.)

RSA blind signatures are vulnerable to decryption by an adversary. As a
precaution, use a different key for both decryption and signing purposes
\[4\].

## In-transit data structures

The initial list of candidates makes sense as an array/list type.

A key-value pair might make more sense to transmit tokens/signatures.

For example, to send the complete collection of *candidate tokens*, the
voter might make a simple JSON object:

<div id="cb1" class="sourceCode">

``` sourceCode
[
    {
        "candidate" : "sanders",
        "token" : tokenize("sanders||voterid")
    }, 
    {
        "candidate" : "trump",
        ...
```

</div>

The registration authority replies with their *blind-signed versions of
each token*:

<div id="cb2" class="sourceCode">

``` sourceCode
[
    {
        "candidate" : "sanders",
        "signature" : blindsign(tokenize("sanders||voterid"))
    }, 
    {
        "candidate" : "trump",
        ...
```

</div>

To cast their votes, the client sends only the ***candidate name, token,
and signature*** for the candidates whom they are voting for:

<div id="cb3" class="sourceCode">


``` sourceCode
[
    {
        "candidate" : "sanders"
        "tokens" : {
            "token" : tokenize("sanders||voterid"),
            "signature" : blindsign(tokenize("sanders||voterid"))
        }
    }, 
    {
        "candidate" : "trump" {
            "tokens" : {
                ...
```

</div>

This approach would be easy to implement.

# References

\[1\] https://crypto.stanford.edu/pbc/notes/crypto/voting.html

\[2\]
https://blog.kuhi.to/rsa\_encryption\_signatures\_and\_blind\_signatures\#4-rsa-blind-signatures

\[3\] https://jeremykun.com/2016/07/05/zero-knowledge-proofs-a-primer/

\[4\]
https://en.wikipedia.org/wiki/Blind\_signature\#Dangers\_of\_RSA\_blind\_signing
