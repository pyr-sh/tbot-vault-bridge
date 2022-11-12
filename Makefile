.PHONY: docker-build docker-push

export DOCKER_REPO=pyrsh/tbot-vault-bridge
export GIT_COMMIT=$(shell git rev-parse --short HEAD)

docker-build:
	docker build -t "${DOCKER_REPO}:${GIT_COMMIT}" .

docker-push: docker-build
	docker push "${DOCKER_REPO}:${GIT_COMMIT}"