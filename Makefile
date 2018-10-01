.PHONY: all
all: p2p

.PHONY: clean
clean:
	rm -f ./p2p

p2p:
	go build -o p2p ./main.go
