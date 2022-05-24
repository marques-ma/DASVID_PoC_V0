# Tear Down All Components
# Delete the workload container:
 kubectl delete deployment client

# Run the following command to delete all deployments and configurations for the agent, server, and namespace:
 kubectl delete namespace spire

# Run the following commands to delete the ClusterRole and ClusterRoleBinding settings:
 kubectl delete clusterrole spire-server-trust-role spire-agent-cluster-role
 kubectl delete clusterrolebinding spire-server-trust-role-binding spire-agent-cluster-role-binding

 kubectl delete pods --all

# Stop and remove minikube environment
minikube stop
minikube delete
