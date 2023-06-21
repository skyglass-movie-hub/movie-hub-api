# Build parameters
OUT?=./target
DOCKER_TMP?=$(OUT)/docker_temp/
DOCKER_TAG?=skyglass/movies-api:1.0.1
BINARY_NAME?=$(OUT)/movies-api-1.0.0.jar

docker-build: build
	rm -rf $(DOCKER_TMP)
	mkdir $(DOCKER_TMP)
	cp $(BINARY_NAME) $(DOCKER_TMP)
	cp ./Dockerfile $(DOCKER_TMP)Dockerfile
	docker buildx build --platform linux/amd64,linux/arm64 -t $(DOCKER_TAG) --push $(DOCKER_TMP)
	rm -rf $(DOCKER_TMP)
build:
	mvn package
docker-push: docker-build
	docker push $(DOCKER_TAG)
clean:
	rm -rf $(OUT)
test: docker-build
	./test.sh

.PHONY: build docker-build docker-push clean
