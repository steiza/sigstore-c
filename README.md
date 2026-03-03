sigstore-c is a Sigstore client library that prioritizes portability over features (and correctness!)

It's written in C89, which allows it to run in old environments with limited resource, like a 16-bit DOS program that only uses the [8086](https://en.wikipedia.org/wiki/Intel_8086) instruction set.

To compile it, you need a C89 compiler for your target architecture and computing environment, like gcc or [Open Watcom v2](https://github.com/open-watcom/open-watcom-v2).

### Usage

First we need some signed data, either from the `testdata` directory or produced with [Cosign](https://github.com/sigstore/cosign):

```
$ echo "Hello, world!" > a.txt
$ cosign generate-key-pair
Enter password for private key:
Enter password for private key again:
Private key written to cosign.key
Public key written to cosign.pub
$ cosign signing-config create > empty.signingconfig.json
$ cosign sign-blob --key cosign.key --signing-config empty.signingconfig.json --bundle signature.sigstore.json a.txt
Enter password for private key:
Using payload from: a.txt
Wrote bundle to file signature.sigstore.json
```

Then you can verify with sigstore-c:

```
$ ./sigstore signature.sigstore.json cosign.pub a.txt
Digest matches
...
Signature verified successfully
```

### "Features"

You might have noticed the usage example didn't sign with sigstore-c; that's because it doesn't support it. It also doesn't support Fulcio certificates, Rekor transparency entries, or signed timestamps. But there is one thing it does support: in-toto attestations (encoded with DSSE, of course)!

```
$ echo "{}" > predicate.json
$ cosign attest-blob --key cosign.key --signing-config empty.signingconfig.json --bundle dsse.sigstore.json --predicate predicate.json --type example-attestation a.txt
Using payload from: a.txt
Using payload from: predicate.json
Enter password for private key:
Wrote bundle to file dsse.sigstore.json
```

And here's the verification:

```
$ ./sigstore dsse.sigstore.json cosign.pub a.txt
Digest matches
...
Signature verified successfully
```

### Frequently Asked Questions

**Q**: Will this run on my PDP-11?

**A**: A suprising number of people ask this. I'm not sure. It should, if you have a C89 compiler and either a PDP-11 or a way to emulate one.


**Q**: Will you add my favorite feature to this?

**A**: Probably not.


**Q**: Should I use this in production?

**A**: Definitely not!
