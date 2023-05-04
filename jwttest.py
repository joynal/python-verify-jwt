"""
Usage:

$ python jwttest.py <JWT token>

"""

import json
import sys

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from jwt.algorithms import ECAlgorithm

certificates = {
    "95df3a1a-07db-4a70-9f8d-365db98c1f8c": "production_key.pem",
    "ee338add-4dd3-42cd-affd-2ffc857c60b2": "test_key.pem",
    "dc47812e-fb20-4fe5-8583-e640fbcbd85a": "local_key.pem",
}


def load_pub_key(kid: str):
    # Load the public key from a PEM file. Return two versions of the key,
    # one loaded straight from the PEM file, and another loaded from JWK
    fname = certificates[kid]
    print(f"loading PEM file: {fname}")
    with open(fname, "rb") as f:
        public_key_pem = f.read()
    from_pem = load_pem_public_key(public_key_pem, backend=default_backend())

    # pymcore stores the public key in JWK format, so do a
    # serialization -> deserialization roundtrip to get the JWK
    jwk = ECAlgorithm.to_jwk(from_pem)
    from_jwk = ECAlgorithm.from_jwk(jwk)
    return from_pem, from_jwk


def test_jwt(token: str, public_key):
    # Verify the signature of the JWT token
    decoded_token = jwt.decode(
        token, public_key, algorithms=["ES256"], audience="pymetrics.com"
    )
    print("JWT verified successfully!")
    # Print the decoded token
    print(json.dumps(decoded_token, indent=2))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        token = sys.argv[1]
    else:
        # Example JWT token
        token = "test"

    # Decode the header of the JWT to get the key ID (kid)
    header = jwt.get_unverified_header(token)
    kid = header["kid"]
    print(f"KID={kid}")
    try:
        pub_key_pem, pub_key_jwk = load_pub_key(kid)
    except KeyError:
        print(f"Unknown KID: {kid}")
        sys.exit(1)

    print("Testing with PEM key")
    test_jwt(token, pub_key_pem)
    print("\nTesting with JWK key")
    test_jwt(token, pub_key_jwk)
