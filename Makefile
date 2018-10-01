.PHONY: all
all: p2p p2p-mac

.PHONY: clean
clean:
	rm -f ./p2p ./p2p-mac

p2p:
	go build -o p2p ./main.go

p2p-mac:
	GOOS=darwin go build -o p2p-mac ./main.go
