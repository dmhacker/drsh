proto:
	protoc -I=. --go_out=. internal/drsh/proto/*.proto
build:
	go build ./...
run:
	go run github.com/dmhacker/drsh/cmd/drsh $(ARGS)
