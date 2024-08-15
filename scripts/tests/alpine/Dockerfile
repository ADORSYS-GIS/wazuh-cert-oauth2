FROM alpine

RUN apk update && apk add curl

# Install dependencies
COPY ./install.sh .

RUN chmod +x install.sh && ./install.sh

RUN yara -v