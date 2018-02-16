FROM alpine:latest

MAINTAINER Edward Muller <edward@heroku.com>

WORKDIR "/opt"

ADD .docker_build/go-getting-started /opt/bin/go-getting-started

CMD ["/opt/bin/go-getting-started"]

