FROM golang

MAINTAINER Eldar Zaitov <eldar@kyprizel.net>

ADD . /go/src/github.com/kyprizel/ct_mon
ADD ./conf/config.json /conf/config.json
RUN go get github.com/tools/godep
RUN cd /go/src/github.com/kyprizel/ct_mon && godep restore && go install
ENTRYPOINT ["/go/bin/ct_mon", "--config=/conf/config.json", "--verbose=false"]
