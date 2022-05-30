#!/bin/bash

echo "Clearing old application"
kubectl delete --all deployments
kubectl delete --all service

echo "Creating subject-wl img"
cd subject_workload
docker build . -t subject-wl 
echo "Loading subject-wl img to minikube"
minikube image load subject-wl

echo "Creating asserting-wl img"
cd ../Assertingwl-mTLS
docker build . -t asserting-wl 
minikube image load asserting-wl
echo "Loading asserting-wl img to minikube"
minikube image load asserting-wl

echo "Creating middle-tier img"
cd ../middle-tier
docker build . -t middle-tier 
echo "Loading middle-tier-wl img to minikube"
minikube image load middle-tier

echo "Creating target-wl img"
cd ../target_workload
docker build . -t target-wl
echo "Loading target-wl img to minikube"
minikube image load target-wl


cd ../Assertingwl-mTLS/
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
