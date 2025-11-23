FROM golang:1.21

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o sshr_bin main.go

EXPOSE 2222

CMD ["./sshr_bin"]
