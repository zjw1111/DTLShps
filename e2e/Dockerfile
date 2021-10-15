FROM golang:buster

COPY . /go/src/github.com/zjw1111/DTLShps
WORKDIR /go/src/github.com/zjw1111/DTLShps/e2e

CMD ["go", "test", "-tags=openssl", "-v", "."]
