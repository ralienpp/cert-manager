#!/bin/bash

echo "Clearing secrets"
kubectl delete -f cert.yml
kubectl delete secret root-secret


echo "Committing changes"
git commit -am "Dummy commit"


echo "Rebuilding environment"
make e2e-setup-certmanager


printf "Done..................\n\n\n\n"
printf "Running new code\n-------------------------------\n\n\n"
kubectl apply -f cert.yml





# kubectl logs -n cert-manager `kubectl get pods -n cert-manager -o jsonpath='{.items[*].metadata.name}' | tr " " "\n" | grep -v cain | grep -v web`