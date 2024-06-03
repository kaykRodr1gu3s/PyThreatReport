# PyThreatReport

## Index

+ 1 - [Overview](#overview)
+ 2 - [Requirements](#requirements)
+ 3 - [Instalation](#instalation)
+ 4 - [Python libraries](#python-libraries)
+ 5 - [Misp on Docker configuration](#misp-on-docker-configuration)
+ 6 - [abuseipdb Api-key](#abuseipdb)
+ 7 - [Executing python code](#executing-python-code)
+ 8 - [MISP Event Overview](#misp-event-overview)
+ 9 - [Contribution](#contribution)
+ 10 - [Contact](#contact)

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
    mkdir documents
    cd documents
    git clone https://github.com/misp/misp-docker
    ```

### Python libraries

  copy and paste this commands

  ```nano
  pip install requests
  pip install pymisp
  ```
  

### Misp on Docker configuration
  After that you create your Linux enviroment and configure with your credencial, let's execute your misp on docker!
  ```
  cd documents/misp-docker
  cp template.env .env
  sudo docker-compose build
  sudo docker-compose up

  ```
  copy and paste these command on command line.

  when the command over, go to your browser and open this url ```https://localhost```, accept the risk and continue.
  when open the localhost, the misp email is `admin@admin.test` the password is `admin`.

  + Organisation
    
    For create a new organisation, go to Administration > Add Organisations. Fill with your datas

    
  + User
    
    For create a new user, go to Administration > Add User

  + Api key

    For you create a Api key, go to Administration > list User on action section, go to view. When click on view option, you will scroll down and click on auth key.  

    
    ![image](https://github.com/kaykRodr1gu3s/PyThreatReport/assets/110197812/9c7e85bb-3e9c-4b0a-b011-1c6bf19c76de)

    click on Add authentication key.


    + Taxonomies

      For you add taxonomies on your event , you need to add the taxonomies, for add go to Event Actions > List Taxonomies. When you click , you will see a search bar o top right, enter with thr tlp value, click on required and enable
      
      ![Captura de tela 2024-04-22 095543](https://github.com/kaykRodr1gu3s/PyThreatReport/assets/110197812/09259303-6d96-4aeb-8c45-65f8088392f5)

      For enable all tpl taxonomiesback to where you was and click on "enable all"
      
      ![Captura de tela 2024-04-22 101310](https://github.com/kaykRodr1gu3s/PyThreatReport/assets/110197812/a3892372-2d25-46c6-b845-79324df248ea)


### Abuseipdb

  For you get a [abuseipdb](https://www.abuseipdb.com/), you need to [create a account](https://www.abuseipdb.com/pricing) or [login](https://www.abuseipdb.com/login). When you create your account go to  API section
  
  ![image](https://github.com/kaykRodr1gu3s/PyThreatReport/assets/110197812/de0486fa-08af-4bd9-9bd1-27908ca7a75a)

  copy the API



### Executing python code
  On your code go to [main code](https://github.com/kaykRodr1gu3s/PyThreatReport/blob/main/main.py) and put your api key that you collect.

  
  
  ![Captura de tela 2024-04-22 005338](https://github.com/kaykRodr1gu3s/PyThreatReport/assets/110197812/af8ba11f-c33d-4619-863c-e861dcfab11a)



  When put your APIs on the code, just need to execute the code.



#### MISP Event Overview


  For see the event created with the API , go to HOME and click on the event view.


  ![Captura de tela 2024-04-22 102624](https://github.com/kaykRodr1gu3s/PyThreatReport/assets/110197812/45db339c-4305-4993-bf30-892dc106bfe4)


  When open the event, you can see the details about the event, like: UUID, Creator org, Owner org, Threat Level, #Attributes and other things.

  For analyse the ips analysed on abuseipdb, just scroll down for see the attributes added

  ![image](https://github.com/kaykRodr1gu3s/PyThreatReport/assets/110197812/d29819c7-2aaa-445c-9606-758b89fea2eb)


  The search on [abuseIPDB](https://www.abuseipdb.com/) about the ips, is located on Comment coloum.



### Contribution

   1. Fork the repository.
   2. Create a branch for your contribution: `git checkout -b feature-nova`.
   3. Make the desired changes and commit: `git commit -m "Add new functionality"`.
   4. Push to your branch: `git push origin new-feature`.
   5. Open a pull request.


### Contact

- Linkedin: [Kayk Rodrigues](https://www.linkedin.com/in/kayk-rodrigues-504a03273)

  
  
  
  
  
  
  
  
  
    






#### 
