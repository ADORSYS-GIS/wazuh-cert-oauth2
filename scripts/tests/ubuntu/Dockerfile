FROM ubuntu

# Install dependencies
COPY ./install.sh .

RUN chmod +x install.sh && ./install.sh

RUN yara -v