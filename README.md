![image](./draw.io/Cluster_RPi_On-Premise.jpg)

## Overview
> The development of this final degree project analyzes, defines and implements a simulation for a new paradigm in telecommunications, known as Fog Computing.  
> This idea tries to bring applications closer the final users, based on three ideas: the microservices architecture, software that allows them to be orchestrated and 5G networks that have new technical characteristics.  
> This BSc thesis will focus on the simulation of the software part, its implementation, and deployment, demonstrating advantages in domestic environments and its potential power in a later development of complex architectures of a productive environment. 

## Resumen del trabajo:

> El desarrollo de este trabajo de final de grado analiza, define e implementa una simulación propuesta para un nuevo paradigma dentro de las telecomunicaciones, denominado como Fog Computing.
> Esta idea trata de acercar las aplicaciones finales a los consumidores,basado en tres ideas: la arquitectura de microservicios, un software que permita orquestarlos y las redes de 5G que tienen nuevas características técnicas. Este TFG, se centrará en la simulación de la parte software, su implementación y despliegue, demostrando ventajas en entornos domésticos y su posible potencia en un posterior desarrollo de arquitecturas complejas.
> Explicación de los documentos y ficheros usados para la ejecución del TFG:

## Demonstration
> https://www.youtube.com/watch?v=t9cPSp5NfcA&feature=youtu.be

## Files

>  -  **docker-webPage** Incluye los ficheros de despliegue y dos scripts de automatización, uno para eliminarlos todos y otro para crearlos:
> -- **app-python:** Fichero de aplicación `app.py` con el script de la página web. Dockerfile para la creación del contenedor y basado en una imagen especifica de ARM (para su uso en RPi). Dos YAML de despliegue uno para aplicaciones en AMD64 y otro para aplicacicones en ARM. Por último un YAML con un objeto Service para definir
> -- **nginx** Carpeta con la configuración propia de nginx (nginx.conf). Carpeta 'www' con varios HTML estáticos de ejemplo y pruebas. Servicios y despliegues de los componentes NGINX.
>  -  **draw.io:** Ficheros XML/JPEG/PNG de los diagramas usados en el proyecto.
>  -  **gcp-live-k8s-visualizer:** Ficheros descargados del repositorio `https://github.com/brendandburns/gcp-live-k8s-visualizer`. Crea un entorno gráfico web para conocer el estado de pods y nodos.
>  -  **http-request-capture:** Ficheros con los sniffer de tráfico: uno para el worker00, otro para el worker01 y el original del repositorio `https://github.com/jacklam718/http-request-capture`.
>  -  **nodeSelector:** Scripts que se ejecutan en las maquinas remotas y modifican la variable `nodeSelector` haciendo que se desplacen los pods de un worker a otro.
>  -  **PPT:** Presentación oficial del Trabajo de Final de Grado.
>  -  **stress:** Script para pruebas de estres en el escalado dinámico de pods. No se uso en el trabajo.
>  -  **waved_net:** Configuración modificada del proxy de red de Kubernetes.



Alberto Crego Matas - Grado en Ingenería de Telecomunicaciones / Telemática
