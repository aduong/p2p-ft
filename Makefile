.PHONY: all
all: p2p-ft p2p-ft-mac

.PHONY: clean
clean:
	rm -f ./p2p-ft ./p2p-ft-mac

p2p-ft:
	go build -o p2p-ft ./main.go

p2p-ft-mac:
	GOOS=darwin go build -o p2p-ft-mac ./main.go
