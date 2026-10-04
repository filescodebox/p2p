BINARY := p2pd
VERSION ?= dev

.PHONY: build test vet lint run smoke docker clean help

build:  ## 构建二进制 → bin/p2pd
	go build -trimpath -ldflags "-w -s -X 'github.com/filescodebox/kit/version.Version=$(VERSION)'" -o bin/$(BINARY) ./cmd/p2pd

test:   ## 全量测试(-race)
	go test -race ./...

vet:
	go vet ./...

lint:   ## golangci-lint(CI 同款门禁)
	golangci-lint run ./...

run: build  ## 本地起服务
	./bin/$(BINARY) --config ./configs/config.yaml

smoke: build  ## 冒烟:健康检查/签名注册/公告/解析/管理端
	bash scripts/smoke.sh

docker:  ## 本地构建镜像
	docker build -t ghcr.io/filescodebox/p2p:dev .

clean:
	rm -rf bin/
