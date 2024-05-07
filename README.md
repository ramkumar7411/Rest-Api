
# Ssapi Python Rest API's




## Environment Variables

To run this project, you will need to add the following environment variables to your .env file

`API_KEY` : http://127.0.0.1:8000/api

Database Details

`HOST` : Database Hostname

`PORT ` : Database Port Number 

`DB_USER` : Database User Name

`DB_PASSWORD ` : Database User Password 

SMPT  Details

`bakendtype` : True

`EMAIL_HOST ` : EMAIL_HOST

`EMAIL_PORT` : EMAIL_PORT 

`EMAIL_USE_TLS ` : True

`EMAIL_HOST_USER ` : EMAIL_HOST_USER/Email Address

`EMAIL_HOST_PASSWORD ` : EMAIL_HOST_PASSWORD








## Installation

 Firsty insatall the Python in the System 
     Python Install Process 
[Python Install Process](https://www.python.org/downloads/)

Django - Create Virtual Environment
[Django - Create Virtual Environment](https://www.w3schools.com/django/django_create_virtual_environment.php)

Install Django
[Install Django](https://www.w3schools.com/django/django_install_django.php)
## Run Locally


Clone the project

```bash
  git clone https://github.com/exoticaitsolutions/ssapi.git
```

Go to the project directory

```bash
  cd ssapi
```

Install Following dependencies

OS Module  
```bash
  import os

```
  simplejwt 
```bash
  pip install djangorestframework-simplejwt
```

 mysqlclient 2.2.4 
```bash
  pip install mysqlclient
```
 python-dotenv
```bash
  pip install python-dotenv
```
Go to the Mail project directory

```bash
  cd ssapi\Rest_api
```
Create the .env File and Copy the value form .env.example

Setup the Database with db name "django_rest_api"
```bash
HOST=HOSTNAME
PORT=PORT 
DB_NAME=DB_NAME
DB_USER=DB_USER
DB_PASSWORD=DB_PASSWORD
```

Setup the Email SMPT
```bash
bakendtype=True
EMAIL_HOST=EMAIL_HOST
EMAIL_PORT=EMAIL_PORT
EMAIL_USE_TLS=True/False
EMAIL_HOST_USER=EMAIL_HOST_USER
EMAIL_HOST_PASSWORD=EMAIL_HOST_PASSWORD
```

Go to the this directory 
```bash
  cd ssapi\Rest_api
```

Run the Migration Cammand 
 ```bash
  python manage.py migrate
```

Run the Serve Using code  
 ```bash
  py manage.py runserver 
```
