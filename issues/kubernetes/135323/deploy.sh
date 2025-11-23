#/bin/bash
set +x

docker build -t registry.local/query .

docker push registry.local/query

kubectl delete -f deployment.yaml > /dev/null 2>&1
kubectl apply -f deployment.yaml

