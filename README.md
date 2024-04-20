# PyThreatReport

## Index

+ 1 - [Overview](#overview)
+ 2 - [Requirements](#requirements)
+ 3 - [Instalation](#instalation)
+ 4 - [Misp on Docker configuration](#misp-on-docker-configuration) 


### Overview

  This Python-based automation tool streamlines the process of collecting, analyzing, and disseminating threat intelligence data. Leveraging the capabilities of the MISP platform, AbuseIPDB API, and Serpro services, the project fetches malicious IP            addresses from a designated URL, enriches this data with insights from AbuseIPDB, and seamlessly integrates the enriched Indicators of Compromise (IoCs) into MISP for comprehensive threat intelligence management.


### Requirements

  For this project we need to install some software and python libraries. they are:
  
  #### Windows
  + Docker
  + WSL
  + git
  + misp
  + python
 

  #### Linux

  + Docker
  + misp
  + git
 



### Instalation
  On instalation you can use linux and windows, i'm going to show how to install onm this both operation system.


  #### Windows
   On windows you need to install some software:
   + [Docker](https://www.docker.com/products/docker-desktop/) for a run container with misp.
   
  + [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) to virtualize a linux enviroment.
  ```bash
     wsl --install
  ```
   or download some linux distribution on microsoft store

   <img width="797" alt="store" src="https://github.com/kaykRodr1gu3s/PyThreatReport/assets/110197812/821673de-6260-4cad-acfe-fedb10007d73">

   + [Git](https://git-scm.com/) for clone the misp repository
   + [Misp](https://github.com/misp/misp-docker) is for build or image in a docker container.
   
   + [Python](https://python.org) for be able to execute python codes.

 
  #### Linux
   On linux enviroment you need to install some software:

   + [Docker](https://docs.docker.com/) for a run container with misp.
     ```nano
      apt-get install docker
     ```
  + [git](https://git-scm.com/) for clone the misp github repository.
    ```
    aot-get install git
    ```
  + [Misp images](https://github.com/misp/misp-docker) to build on container.
    ```git

    git clone https://github.com/misp/misp-docker
    ```




### Misp on DOcker configuration
  After that you create your Linux enviroment and configure with your credencial, let's execute your misp image!

  



####
