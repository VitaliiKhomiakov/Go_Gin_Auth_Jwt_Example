FROM golang:1.22

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /

RUN go mod download github.com/BurntSushi/toml@v1.3.2
RUN go mod download gorm.io/gorm@v1.25.9
RUN go install github.com/cosmtrek/air@v1.51

COPY ./app /app

WORKDIR /app

#RUN go mod tidy
#CMD ["air", "init"]

CMD ["air"]
