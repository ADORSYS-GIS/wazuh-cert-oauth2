FROM ubuntu

RUN apt-get update && apt-get install -y curl

# Install dependencies
COPY ./install.sh .

RUN chmod +x install.sh && ./install.sh

RUN yara -v