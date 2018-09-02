#!/bin/sh

echo Desplazando Pods al worker01...
kubectl patch deployment flask-python -p='{"apiVersion": "extensions/v1beta1","kind": "Deployment","metadata": {"name": "flask-python","labels": {"app": "flask-python"}},"spec": {"replicas": 2,"selector": {"matchLabels": {"app": "flask-python"}},"template": {"metadata": {"labels": {"app": "flask-python"}},"spec": {"containers": [{"name": "flask-python","image": "acrego/app-python-arm32:1.0","ports": [{"containerPort": 5000,"name": "http","protocol": "TCP"}],"imagePullPolicy": "Always","env": [{"name": "MY_NODE_NAME","valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},{"name": "MY_NODE_NAME","valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},{"name": "MY_NODE_IP","valueFrom": {"fieldRef": {"fieldPath": "status.hostIP"}}},{"name": "MY_POD_NAME","valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},{"name": "MY_POD_NAMESPACE","valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},{"name": "MY_POD_IP","valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}},{"name": "MY_POD_SERVICE_ACCOUNT","valueFrom": {"fieldRef": {"fieldPath": "spec.serviceAccountName"}}}]}],"nodeSelector": {"tfg": "worker01"}}}}}'
kubectl patch deployment web-nginx -p='{"apiVersion":"extensions/v1beta1","kind":"Deployment","metadata":{"name":"web-nginx","labels":{"app":"nginx"}},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"nginx"}},"template":{"metadata":{"labels":{"app":"nginx"}},"spec":{"containers":[{"name":"nginx","image":"nginx","ports":[{"containerPort":8080}],"volumeMounts":[{"name":"www-volume","mountPath":"/usr/share/nginx/html"},{"name":"config-volume","mountPath":"/etc/nginx/nginx.conf","subPath":"nginx.conf"}]}],"volumes":[{"name":"www-volume","configMap":{"name":"www-nginx"}},{"name":"config-volume","configMap":{"name":"nginx-conf"}}],"nodeSelector":{"tfg":"worker01"}}}}}'

sleep 5