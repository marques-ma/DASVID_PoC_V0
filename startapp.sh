#!/bin/bash

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
