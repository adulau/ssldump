"""Check complete FAN/1 X.509 fingerprints through the certificate parser."""

import base64
import hashlib
import json
import subprocess
import sys


def main():
    result = subprocess.run(
        [sys.argv[1], "-n", "-j", "-N", "-r", sys.argv[2]],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    certificates = 0
    for line in result.stdout.splitlines():
        record = json.loads(line)
        for certificate in record.get("cert_chain", []):
            features = certificate["fan1_x509_features"].encode("utf-8")
            encoded = base64.urlsafe_b64encode(features).rstrip(b"=").decode("ascii")
            digest = hashlib.sha256(features).hexdigest()
            expected = "fan1:x509:server:passive:{}:sha256:{}".format(encoded, digest)
            if certificate["fan1_x509_fp"] != expected:
                raise AssertionError("Incomplete or incorrect FAN/1 X.509 fingerprint")
            certificates += 1
    if certificates == 0:
        raise AssertionError("No X.509 certificates were checked")
    print("Verified {} FAN/1 X.509 fingerprint(s)".format(certificates))


if __name__ == "__main__":
    main()
