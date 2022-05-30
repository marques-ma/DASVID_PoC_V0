#/bin/bash


# Create spire-server entries to spire-agent, frontend, frontend-2 and backend.

set -e

bb=$(tput bold)
nn=$(tput sgr0)

register() {
    kubectl exec -n spire spire-server-0 -c spire-server -- /opt/spire/bin/spire-server entry create $@
}

echo "${bb}Creating agent registration entry for the node...${nn}"
register \
    -node  \
    -spiffeID spiffe://example.org/spire-agent \
    -selector k8s_sat:agent_ns:spire \
    -selector k8s_sat:agent_sa:spire-agent

echo "${bb}Creating registration entry for the subject workload...${nn}"
register \
    -parentID spiffe://example.org/spire-agent \
    -spiffeID spiffe://example.org/subject_wl \
    -selector k8s:ns:default \
    -selector k8s:sa:default \
    -selector k8s:pod-label:app:subject-wl

echo "${bb}Creating registration entry for the asserting workload...${nn}"
register \
    -parentID spiffe://example.org/spire-agent \
    -spiffeID spiffe://example.org/asserting_wl \
    -selector k8s:ns:default \
    -selector k8s:sa:default \
    -selector k8s:pod-label:app:asserting-wl

echo "${bb}Creating registration entry for the middle tier...${nn}"
register \
    -parentID spiffe://example.org/spire-agent \
    -spiffeID spiffe://example.org/middletier \
    -selector k8s:ns:default \
    -selector k8s:sa:default \
    -selector k8s:pod-label:app:middle-tier

echo "${bb}Creating registration entry for the target workload...${nn}"
register \
    -parentID spiffe://example.org/spire-agent \
    -spiffeID spiffe://example.org/target_wl \
    -selector k8s:ns:default \
    -selector k8s:sa:default \
    -selector k8s:pod-label:app:target-wl

echo "${bb}Listing created registration entries...${nn}"
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry show
