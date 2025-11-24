FROM golang:1.21

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go mod tidy
RUN go build -o sshr_bin .

EXPOSE 2222

CMD ["./sshr_bin"]
