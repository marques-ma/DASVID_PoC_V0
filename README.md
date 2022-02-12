# Asserting Workload --prototype-- 

This application exposes an API that allow callers to send an OAuth Token (Okta or Google) and receive a new JWT token (DA-SVID) that binds the original subject to caller workload, in that a way that caller workload can act in behalf of original Oauth token subject claim (end-user).

## Prerequisites

- SPIRE-Server and Agent up and running
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
    -spiffeID spiffe://example.org/target_wl \
    -selector docker:label:type:targetwl 
    
spire-server entry create \
    -parentID spiffe://example.org/host \
    -spiffeID spiffe://example.org/middletier \
    -selector docker:label:type:middletier 
```

- Users subject_wl and target_wl, to execute locally the components and simulate different client calls  
- Go and/or Docker

To execute in a Docker container
```
docker build . -t asserting_wl
docker run -p 8443:8443 -v /tmp/spire-agent/public/api.sock:/tmp/spire-agent/public/api.sock -d asserting_wl
```

# How it works

To access the API, clients must stablish a mTLS connection with Asserting Workload using its SVID. The asserting workload accepts any connection originated from a predefined trust domain (usually itselfs), and clients should accept connections only from specific predefined list of SPIFFE-IDs.  
When connected, clients can access /keys or /mint endpoints.

See a client example in ./client/main.go  

# /keys endpoint
Does not require any parameter, and returns the public key set to validate DA-SVIDs.

# /mint endpoint
Require a OKTA or Google OAuth token as AccessToken parameter. 

When a mint call is received, the Asserting Workload validate the OAuth token received. If the token is valido, it fetchs the SPIFFE-ID from the current mTLS session and uses it as DA-SVID subject claim. Asserting Workload fetchs its SPIFFE-ID and use it as DA-SVID issuer claim.  

After DA-SVID claims generation, the token is signed with Asserting Workload private key, that could be its SVID or another specific key. The current implementation uses a specific key, localized in ./keys.  

In the end, the Asserting Workload sends to client Oauth token expiration and signature validation results and the generated DA-SVID.

# References

[OIDC Web Setup Instructions]: https://developer.okta.com/authentication-guide/implementing-authentication/auth-code#1-setting-up-your-application
