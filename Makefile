all: build

build:
	gcc -g src/main.c src/base64.c src/sha256.c src/ecdsa.c src/cjson/cJSON.c -o sigstore

test: build
	./sigstore testdata/simple.sigstore.json testdata/cosign.pub testdata/a.txt
	./sigstore testdata/dsse.sigstore.json testdata/cosign.pub testdata/a.txt
