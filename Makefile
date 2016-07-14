test:
	docker build -t psvmi:test -f Dockerfile.test .
	docker run -it psvmi:test bash tests/test.sh
