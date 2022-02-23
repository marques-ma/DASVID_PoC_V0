# Transitive Identity & Embedded Claims
## Proof of Concept

This Proof of Concept simulates a banking application with two frontends: Subject Workload and Subject Workload Mobile. The business logic says that only Subject Workload is allowed to use DA-SVIDs to act in behalf of end-user and access specific functions as check balance and make deposits.

In this scenario, each component is a workload with a SPIFFE-ID running in a Docker container. Asserting Workload is a trusted component allowed to mint new DA-SVID tokens. When the the application frontend needs to access end-user data, it stablish an SPIRE mTLS connection with Asserting Workload, sending the end-user OAuth token. The Asserting Workload, by its side, receives the OAuth token, mint a DA-SVID (claims described at ... ref doc...) and sign with its private key (can be its SVID or another specific key), sending back to subject workload.

Middle tier simulates a generic cloud application component (e.g. load balancer), to exemplify DA-SVID transitivity. In this PoC, when receive requests that uses DA-SVID, it first validate its expiration and signature. After that, middle tier uses Asserting Workload introspect endpoint to validate the DA-SVID. Requests with valid DA-SVID are send to Target Workload.

When Target Workload receives a request with DA-SVID, it also check its expiration and signature. If the token is valid, Target Workload parse its claims and verify if DA-SVID subject claim is allowed to use DA-SVID. Then, TW extract dpr claim and perform a database search for that user, returning user balance or error message.

## Prerequisites

- OKTA account (Application with client ID, client Secret and authorized callback URI.
- Docker
- SPIRE-Server and Agent (host) up and running
- SPIRE entries:
```
spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/asserting_wl \
    -selector docker:label:type:assertingwl
    
spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/subject_wl \
    -selector docker:label:type:subjectwl
    
spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/subject_mob \
    -selector docker:label:type:subjectmob
    
spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/target_wl \
    -selector docker:label:type:targetwl 
    
spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier \
    -selector docker:label:type:middletier 
```

Alternatively, you can run startenv.sh to start a new SPIRE server and agent and create the necessary entries.

To execute the Proof of concept components, go to component directory, build and run docker image, exposing necessary ports and mapping correct UDS volume as example:

```
docker build . -t <asserting_wl/subject_wl/middle_tier/target_wl>
docker run -p <8443:8443/8080/8445/8444> -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d <asserting_wl/subject_wl/middle_tier/target_wl>
```

# How it works

Asserting Workload is the main component that is responsible for Oauth token validation and DA-SVID minting. To perform its tasks, Asserting WL exposes an API with the necessary endpoints described bellow. All API responses are in JSON format.

To access the API, clients must stablish a mTLS connection with Asserting Workload using its SVID. Asserting workload accepts any connection originated from its trust domain, and clients should accept connections only from specific predefined SPIFFE-IDs (Asserting Workload).  

When connected, clients can access /keys, /mint and /introspect endpoints.

# /keys
This endpoint does not require any parameter, and returns the public key set necessary to validate DA-SVIDs.

# /mint
Require a OKTA or Google OAuth token as _AccessToken_ parameter. 

When a mint call is received, the Asserting Workload validate the OAuth token received. If the token is valid, it fetchs the SPIFFE-ID from the current mTLS session and uses it as DA-SVID subject claim. Asserting Workload also fetchs its own SPIFFE-ID and use it as DA-SVID issuer claim.  

After DA-SVID claims generation, the token is signed with Asserting Workload private key, that could be its SVID or another specific key. The current implementation uses a specific key, localized in ./keys.  

In the end, the Asserting Workload sends to client Oauth token expiration and signature validation results and the generated DA-SVID.

# /introspect
Requires a DA-SVID as parameter.  

This endpoint return the DA-SVID original claims and a proof that a valid OAuth token was used to generate that DA-SVID.

# References

[OIDC Web Setup Instructions]: https://developer.okta.com/authentication-guide/implementing-authentication/auth-code#1-setting-up-your-application


