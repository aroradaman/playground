#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

dest="${HOME}/.private-registry"
alias="registry.local"
netdev="wlo1"

mkdir -p ${dest} ${dest}/certs ${dest}/data

ip=$(ip addr show dev ${netdev} |  grep -oP 'inet \K[\d.]+')
if ! grep -q "${alias}" /etc/hosts; then
  echo "${ip} ${alias}" | sudo tee -a /etc/hosts > /dev/null
fi


openssl req -newkey rsa:4096 -nodes -sha256 -keyout ${dest}/certs/${alias}.key -x509 -days 365 \
  -out ${dest}/certs/${alias}.crt -subj "/CN=${alias}" \
  -addext "subjectAltName=DNS:${alias},IP:${ip}"

docker kill registry || echo "not running"
docker container rm registry || echo "not running"

docker run -d -p 443:443 --restart=always \
  -v ${dest}/certs/${alias}.crt:/certs/${alias}.crt \
  -v ${dest}/certs/${alias}.key:/certs/${alias}.key \
  -v ${dest}/data/:/var/lib/registry \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:443 \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/${alias}.crt \
  -e REGISTRY_HTTP_TLS_KEY=/certs/${alias}.key \
  --name registry registry:2

sudo mkdir -p /etc/docker/certs.d/${alias}
sudo cp ${dest}/certs/${alias}.crt /etc/docker/certs.d/${alias}/ca.crt

sudo mkdir -p /usr/local/share/ca-certificates/
sudo cp ${dest}/certs/${alias}.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

set +e

for container in $(docker ps --format '{{.Names}}')
do
  docker cp ${dest}/certs/${alias}.crt ${container}:/usr/local/share/ca-certificates/
  docker exec ${container} update-ca-certificates
  docker exec ${container} update-ca-certificates
  docker exec ${container} systemctl restart containerd
  docker exec ${container} systemctl restart kubelet
  echo "updated certs for ${container}"
done

if kubectl get namespace kapp-controller; then
  echo "kapp-controller namespace found"
  if kubectl get deployment kapp-controller --namespace kapp-controller -o json | jq -e '.spec.template.spec.volumes[]? | select(.name=="cert")' > /dev/null; then
    echo "kapp-controller already has registry certificate"
  else
    echo "kapp-controller does not have private registry certificate"
    kubectl patch deployment kapp-controller --namespace kapp-controller \
      --type='json' \
      --patch='[
        {"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": "cert","hostPath": {"path": "/usr/local/share/ca-certificates/'${alias}'.crt","type": "File"}}},
        {"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts/-", "value": {"name": "cert","mountPath": "/etc/ssl/certs/'${alias}'.crt"}},
        {"op": "add", "path": "/spec/template/spec/containers/1/volumeMounts/-", "value": {"name": "cert","mountPath": "/etc/ssl/certs/'${alias}'.crt"}},
      ]'
  fi
fi