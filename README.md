# slageneratorV3
slageneratorV3 Repository is an client-server application that provides a tool to obtain a threat modeling of a particular system, provided that it has been modeled in MACM model.

The application is developed using the following technologies:

## SERVER-SIDE
* Python 3
* Django framework
* SQLlite
## CLIENT-SIDE
* HTML, CSS (BOOTSTRAP)
## Graph Database
Neo4j is used to collect the MACMs. 
Before starting the application, neo4j must be installed, running on port 7474 and the neo4j credentials configured on credentials.py file.

## Configuration guide
### Software Requirements

* Python 3
* Django
* SQLite

**N.B.:** In order to use and start the application you need to:

* Install django using command: bash pip3 install Django

* Run server typing: bash python3 manage.py runserver

App available on: http://127.0.0.1:8000
