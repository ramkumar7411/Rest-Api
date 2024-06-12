# Project Name
## Ssapi Python Rest API's
# Description 
* This project consists of various APIs developed using Django restfrawework.

# Setup Instructions

## Installation
### Python Install Process 
Before proceeding, ensure Python is installed on your system. If not, you can download and install Python from [here](https://www.python.org/downloads/).

### Django - Setting up a Virtual Environment
To work with Django, it's recommended to create a virtual environment. Follow the steps outlined [here](https://www.w3schools.com/django/django_create_virtual_environment.php) to create one.

### Installing Django
Once the virtual environment is set up, you can install Django within it. Refer to [this guide](https://www.w3schools.com/django/django_install_django.php) for detailed instructions on installing Django.


# Getting Started

Clone the project

```bash
  git clone https://github.com/exoticaitsolutions/ssapi.git
```

## Go to the project directory

```bash
  cd ssapi
```
## Go to the main project
```
  cd ssapi\Rest_api
```

# Install Dependencies
Using requirements.txt
```
pip install -r requirements.txt
```
## Individual Dependencies
djangorestframework-simplejwt 
```bash
  pip install djangorestframework-simplejwt
```
mysqlclient
```bash
  pip install mysqlclient
```
python-dotenv
```bash
  pip install python-dotenv
```

# Create .env file
## For linux
touch .env

## For Windows
type null > .env

## Environment Variables
* To run this project, you'll need to set the following environment variables in your .env file:



# Database Details
```bash
HOST=HOSTNAME
PORT=PORT 
DB_NAME=DB_NAME
DB_USER=DB_USER
DB_PASSWORD=DB_PASSWORD
```

SMPT  Details
```bash
bakendtype=True
EMAIL_HOST=EMAIL_HOST
EMAIL_PORT=EMAIL_PORT
EMAIL_USE_TLS=True/False
EMAIL_HOST_USER=EMAIL_HOST_USER
EMAIL_HOST_PASSWORD=EMAIL_HOST_PASSWORD
```

Run the Migration Cammand 
 ```bash
  python manage.py migrate
```

Run the Serve Using code  
 ```bash
  python manage.py runserver 
```
