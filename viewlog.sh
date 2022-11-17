#!/bin/bash

kubectl logs -n cert-manager `kubectl get pods -n cert-manager -o jsonpath='{.items[*].metadata.name}' | tr " " "\n" | grep -v cain | grep -v web`
