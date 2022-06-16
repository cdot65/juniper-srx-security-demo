FROM python:slim-buster

### -------------------------------------------------
### Metadata information
### -------------------------------------------------
LABEL name="juniper-srx-security-demo"
LABEL maintainer="cremsburg.dev@gmail.com"
LABEL description="Python container to test automation with"
LABEL license="GPLv3"
LABEL url="https://github.com/cdot65/juniper-srx-security-demo"
LABEL build-date="20220616"

### -------------------------------------------------
### Change directory to /tmp/files
### -------------------------------------------------
WORKDIR /tmp/files

### -------------------------------------------------
### Change directory to /tmp/files
### -------------------------------------------------
RUN apt -y update
RUN apt -y install sshpass

### -------------------------------------------------
### Add and install python packages
### -------------------------------------------------
ADD requirements.txt requirements.txt
RUN pip install -r requirements.txt
RUN pip install --upgrade pip

### -------------------------------------------------
### Create an SSH config file to bypass SSH key check
### -------------------------------------------------
WORKDIR /root/.ssh
RUN echo "Host *\n    StrictHostKeyChecking no" > /root/.ssh/config
