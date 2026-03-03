all: build

build:
	gcc -g src/main.c src/base64.c src/sha256.c src/ecdsa.c src/cjson/cJSON.c -o sigstore

dos16:
	/snap/open-watcom/2/binl64/wcc src/main.c -fo=.obj -i=/snap/open-watcom/2/h -bt=dos
	/snap/open-watcom/2/binl64/wcc src/base64.c -fo=.obj -i=/snap/open-watcom/2/h -bt=dos
	/snap/open-watcom/2/binl64/wcc src/sha256.c -fo=.obj -i=/snap/open-watcom/2/h -bt=dos
	/snap/open-watcom/2/binl64/wcc src/ecdsa.c -fo=.obj -i=/snap/open-watcom/2/h -bt=dos
	/snap/open-watcom/2/binl64/wcc src/cjson/cJSON.c -fo=.obj -i=/snap/open-watcom/2/h -bt=dos
	INCLUDE=/snap/open-watcom/current/lh && WATCOM=/snap/open-watcom/2 && /snap/open-watcom/2/binl64/wlink Name SIGSTORE Format Dos LIBPath /snap/open-watcom/2/lib286/dos Library /snap/open-watcom/2/lib286/math87s.lib File base64.obj,cJSON.obj,ecdsa.obj,main.obj,sha256.obj

test: build
	./sigstore testdata/simple.sigstore.json testdata/cosign.pub testdata/a.txt
	./sigstore testdata/dsse.sigstore.json testdata/cosign.pub testdata/a.txt
