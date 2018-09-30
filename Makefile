.PHONY: all
all: send receive

.PHONY: clean
clean:
	rm -f send receive

send:
	go build ./send.go ./common.go

receive:
	go build ./receive.go ./common.go
