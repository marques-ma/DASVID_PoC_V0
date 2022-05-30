#!/bin/bash

docker build . -t asserting-wl
kubectl delete deployment asserting-wl
sleep 3
minikube image rm docker.io/library/asserting-wl
minikube image load asserting-wl
kubectl apply -f deployment.yaml
