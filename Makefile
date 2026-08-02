all: build

build:
	gcc -g src/cjson/cJSON.c src/base64.c  src/ecdsa.c src/file.c src/mldsa.c src/sha256.c src/shake.c src/main.c -o sigstore

dos16:
	/snap/open-watcom/2/binl64/wcc src/base64.c -fo=.obj -i=/snap/open-watcom/2/h -0 -bt=dos
	/snap/open-watcom/2/binl64/wcc src/cjson/cJSON.c -fo=.obj -i=/snap/open-watcom/2/h -0 -bt=dos
	/snap/open-watcom/2/binl64/wcc src/ecdsa.c -fo=.obj -i=/snap/open-watcom/2/h -0 -bt=dos
	/snap/open-watcom/2/binl64/wcc src/file.c -fo=.obj -i=/snap/open-watcom/2/h -0 -bt=dos
	/snap/open-watcom/2/binl64/wcc src/mldsa.c -fo=.obj -i=/snap/open-watcom/2/h -0 -bt=dos
	/snap/open-watcom/2/binl64/wcc src/sha256.c -fo=.obj -i=/snap/open-watcom/2/h -0 -bt=dos
	/snap/open-watcom/2/binl64/wcc src/shake.c -fo=.obj -i=/snap/open-watcom/2/h -0 -bt=dos
	/snap/open-watcom/2/binl64/wcc src/main.c -fo=.obj -i=/snap/open-watcom/2/h -0 -bt=dos
	INCLUDE=/snap/open-watcom/current/lh && WATCOM=/snap/open-watcom/2 && /snap/open-watcom/2/binl64/wlink Name SIGSTORE Option stack=0x8000 Format Dos LIBPath /snap/open-watcom/2/lib286/dos Library /snap/open-watcom/2/lib286/math87s.lib File base64.obj,cJSON.obj,ecdsa.obj,file.obj,main.obj,mldsa.obj,sha256.obj,shake.obj

test: build
	./sigstore testdata/simple.sigstore.json testdata/cosign.pub testdata/a.txt
	./sigstore testdata/dsse.sigstore.json testdata/cosign.pub testdata/a.txt
