REPO    ?= github.com/kubenav/bind
VERSION ?= $(shell git describe --tags)

.PHONY: bindings-android bindings-ios dependencies release-major release-minor release-patch test

bindings-android:
	GO111MODULE=off gomobile bind -o request.aar -target=android ${REPO}/request
	tar -zcvf request.aar-${VERSION}-android.tar.gz request.aar

bindings-ios:
	GO111MODULE=off gomobile bind -o Request.framework -target=ios ${REPO}/request
	tar -zcvf Request.framework-${VERSION}-ios.tar.gz Request.framework

dependencies:
	GO111MODULE=off go get -u golang.org/x/mobile/cmd/gomobile
	GO111MODULE=off go get -u github.com/aws/aws-sdk-go/...

release-major:
	$(eval MAJORVERSION=$(shell git describe --tags --abbrev=0 | sed s/v// | awk -F. '{print $$1+1".0.0"}'))
	git checkout master
	git pull
	git tag -a $(MAJORVERSION) -m 'Release $(MAJORVERSION)'
	git push origin --tags

release-minor:
	$(eval MINORVERSION=$(shell git describe --tags --abbrev=0 | sed s/v// | awk -F. '{print $$1"."$$2+1".0"}'))
	git checkout master
	git pull
	git tag -a $(MINORVERSION) -m 'Release $(MINORVERSION)'
	git push origin --tags

release-patch:
	$(eval PATCHVERSION=$(shell git describe --tags --abbrev=0 | sed s/v// | awk -F. '{print $$1"."$$2"."$$3+1}'))
	git checkout master
	git pull
	git tag -a $(PATCHVERSION) -m 'Release $(PATCHVERSION)'
	git push origin --tags

test:
	GO111MODULE=off go test -v ./...
