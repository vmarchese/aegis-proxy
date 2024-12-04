# Makefile

# Variables
IMAGE_NAME := aegis-proxy
TAG := latest
DOCKERFILE := Dockerfile
BUILD_DIR := .

GOVERSION=$(shell go version)
USER=$(shell id -u -n)
TIME=$(shell date)



# Targets
.PHONY: all image push clean

all: image

image:
	docker build -t $(IMAGE_NAME):$(TAG) \
	--build-arg VERSION=$(TAG) \
	--build-arg GOVERSION="$(GOVERSION)" \
	--build-arg BUILDUSER="$(USER)" \
	--build-arg BUILDTIME="$(TIME)" \
	-f $(DOCKERFILE) $(BUILD_DIR)

push:
	docker push $(IMAGE_NAME):$(TAG)

clean:
	docker rmi $(IMAGE_NAME):$(TAG) || true
