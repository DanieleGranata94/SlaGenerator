# slageneratorV3
slageneratorV3 Repository is an client-server application that provides a tool to obtain a threat modeling of a particular system, provided that it has been modeled in MACM model.


## Technologies
The application is developed using the following technologies:

 * SERVER-SIDE
 * CLIENT-SIDE
 * Graph Database


### SERVER-SIDE
The server side technologies are:

 * Python 3
 * Django framework
 * SQLlite


### CLIENT-SIDE
The client side technologies are:

 * HTML, CSS (BOOTSTRAP)


### Graph Database
Neo4j is used to collect end to store the MACM models.
Before starting the application, neo4j must be installed, running on port 7474 and the neo4j credentials configured on credentials.py file.
Before starting the application it is important to:

 1. install neo4j
 2. run neo4j on port 7474
 3. use the same neo4j credentials as configured on credentials.py file.

**N.B.:** The credentials are intended for local use.
It is highly recommended to generate strong credentials.


## Configuration guide


### Software Requirements
The software requirements are:

 * Python 3
 * Django
 * SQLite


### Setup
**N.B.:** In order to use and start the application you need to:

1. Install django using command: bash pip3 install Django
2. Run server typing: bash python3 manage.py runserver

App available on: http://127.0.0.1:8000
