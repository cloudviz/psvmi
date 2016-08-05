test:
	docker build -t psvmi:test -f Dockerfile.test .
	docker run -it --privileged psvmi:test bash  tests/test.sh 'NEW_VM'

testRunningVM: 
	docker run -it --privileged --pid=host  psvmi:test bash tests/test.sh 'RUNNING_VM' 
