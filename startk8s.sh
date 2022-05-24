#/bin/bash
#

# Tested on Ubuntu 20.04
# Prereqs:
# - Docker, Docker-compose, minikube, kubectl

# Start minikube using extra-configs demanded by SPIRE. I had to add --driver=none otherwise minikube startup fails due to some proxy error.
minikube start \
    --extra-config=apiserver.service-account-signing-key-file=/var/lib/minikube/certs/sa.key \
    --extra-config=apiserver.service-account-key-file=/var/lib/minikube/certs/sa.pub \
    --extra-config=apiserver.service-account-issuer=api \
    --extra-config=apiserver.service-account-api-audiences=api,spire-server \
    --extra-config=apiserver.authorization-mode=Node,RBAC \

sleep 3

# Based on spire-tutorials repo: https://github.com/spiffe/spire-tutorials.git
cd /spire-tutorials/k8s/quickstart

##################

# Create the namespace:
kubectl apply -f spire-namespace.yaml
sleep 3
kubectl get namespaces

# Create the server’s service account, configmap and associated role bindings as follows:
kubectl apply \
    -f server-account.yaml \
    -f spire-bundle-configmap.yaml \
    -f server-cluster-role.yaml
sleep 3

# Deploy the server configmap and statefulset by applying the following files via minikube kubectl --:
kubectl apply \
    -f server-configmap.yaml \
    -f server-statefulset.yaml \
    -f server-service.yaml
sleep 3
kubectl get statefulset --namespace spire

# To allow the agent read access to the kubelet API to perform workload attestation, 
# a Service Account and ClusterRole must be created that confers the appropriate entitlements 
# to Kubernetes RBAC, and that ClusterRoleBinding must be associated with the service account 
# created in the previous step.
kubectl apply \
    -f agent-account.yaml \
    -f agent-cluster-role.yaml
sleep 3

# Apply the agent-configmap.yaml configuration file to create the agent configmap and deploy the 
# Agent as a daemonset that runs one instance of each Agent on each Kubernetes worker node.
kubectl apply \
    -f agent-configmap.yaml \
    -f agent-daemonset.yaml

# Longer sleep, giving time to initialization
sleep 45

# Check if everything is running
kubectl get daemonset --namespace spire
kubectl get pods --namespace spire


cd ./Assertingwl-mTLS
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

cd ../subject_workload
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

cd ../middle-tier
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

cd ../target_workload
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
