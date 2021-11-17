import sys
import re
import math
import base64
import time
from cose.messages.sign1message import Sign1Message
from cose.headers import Algorithm, KID
from cose.algorithms import Es256
import cbor2

# TODO: Is this dynamic in some way? The examples in the specifications don't match
VALID_ISSUERS = ['did:web:nzcp.identity.health.nz']
# TODO: Fetch this from https://nzcp.identity.health.nz/.well-known/did.json
ISSUER_KEYS = {
	"id": "did:web:nzcp.identity.health.nz",
	"@context": [
		"https://w3.org/ns/did/v1",
		"https://w3id.org/security/suites/jws-2020/v1"
	],
	"verificationMethod": [
		{
			"id": "did:web:nzcp.identity.health.nz#z12Kf7UQ",
			"controller": "did:web:nzcp.identity.health.nz",
			"type": "JsonWebKey2020",
			"publicKeyJwk": {
				"kty": "EC",
				"crv": "P-256",
				"x": "DQCKJusqMsT0u7CjpmhjVGkHln3A3fS-ayeH4Nu52tc",
				"y": "lxgWzsLtVI8fqZmTPPo9nZ-kzGs7w7XO8-rUU68OxmI"
			}
		}
	],
	"assertionMethod": [
		"did:web:nzcp.identity.health.nz#z12Kf7UQ"
	]
}

if len(sys.argv) != 2:
	print('Usage: python3 vaccine-verify.py <payload>')
	exit(1)

key = sys.argv[1]

# Make sure format matches what we expect
pattern = r'^NZCP:\/(\d+)\/(.+)$'
match = re.search(pattern, key)
if match is None:
	print('Invalid payload')
	exit(1)
version = match.group(1)
encoded_payload = match.group(2)
print(f'Using version {version}')

# Pad the base32 string so that we can decode it
padding_length = math.ceil(len(encoded_payload) / 8) * 8 - len(encoded_payload)
decoded_payload = base64.b32decode(encoded_payload + '=' * padding_length)

decoded_payload = Sign1Message.decode(decoded_payload)

headers = decoded_payload.phdr
payload = cbor2.loads(decoded_payload.payload)
print(f'Got payload {payload}')

# Verify headers
if not headers.get(KID) or not headers.get(Algorithm):
	print('Headers are missing')
	exit(1)
if headers.get(Algorithm) != Es256:
	print('Algorithm does not match')
	exit(1)

# Find all the expected headers
cwt_token_id = payload[7]
issuer = payload[1]
not_before = payload[5]
expiry = payload[4]
verifiable_claim = payload['vc']

# Validate issuer is one we trust
print(f'Issued by {issuer}')
if issuer not in VALID_ISSUERS:
	print('Invalid issuer')
	exit(1)

key_reference = f'{issuer}#{headers.get(KID).decode()}'
if key_reference not in ISSUER_KEYS.get('assertionMethod', []):
	print('Verification method not found')
	exit(1)

jwk_key = None
for method in ISSUER_KEYS.get('verificationMethod', []):
	if method['id'] == key_reference:
		if method['type'] != 'JsonWebKey2020':
			print('Verification method is the wrong type')
			exit(1)
		if method['publicKeyJwk'].get('crv') != 'P-256' or method['publicKeyJwk'].get('kty') != 'EC':
			print('JWK is not valid')
			exit(1)
		jwk_key = method['publicKeyJwk']
if jwk_key is None:
	print('JWK not found')
	exit(1)

# TODO: Is this just the above grabbing of jwk_key?
# With the retrieved public key validate the digital signature over the
# COSE_Sign1 structure, if an error occurs then fail.

# Validate all of the claims
print(f'Unique ID {cwt_token_id}')  # TODO: decode and make sure its a valid UUID
print(f'Issuer matches? {issuer in VALID_ISSUERS}')
print(f'Active? {not_before < int(time.time())}')
print(f'Expired? {expiry < int(time.time())}')
print(f'Verifiable Claim {verifiable_claim}')  # TODO: validate this https://nzcp.covid19.health.nz/#verifiable-credential-claim-structure
