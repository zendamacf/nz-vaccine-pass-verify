import binascii
from os.path import exists as file_exists
import sys
import re
from math import ceil
from base64 import b32decode, urlsafe_b64decode
import time
from datetime import datetime
import json
from logging import getLogger
from urllib.request import urlopen
from urllib.error import URLError
from cose.messages.sign1message import Sign1Message
from cose.headers import Algorithm, KID
from cose.algorithms import Es256
from cose.keys import EC2Key
from cose.keys.keytype import KtyEC2
import cbor2
import exceptions

VALID_ISSUERS = ['did:web:nzcp.identity.health.nz']
PASS_TYPES = {'PublicCovidPass': ['givenName', 'familyName', 'dob']}
SPEC_VERSION = 1
SPEC_VERSION_LONG = '1.0.0'
LOGGER = getLogger(__name__)


def fetch_did_document(did_web_url):
	did_doc = None
	url = re.match(r'^did:web:(.+)$', did_web_url).group(1)
	did_file = f'{url}.key'

	if file_exists(did_file):
		# Use cached copy of public key
		LOGGER.debug(f'Using cached key file for {url}')
		with open(did_file, 'r') as f:
			did_doc = json.load(f)
	else:
		# Fetch remote public key
		LOGGER.debug(f'Fetching key file from {url}')
		full_url = f'https://{url}/.well-known/did.json'
		try:
			json_resp = urlopen(full_url)
			with open(did_file, 'w') as f:
				content = json_resp.read().decode()
				f.write(content)
				did_doc = json.loads(content)
		except URLError:
			LOGGER.error(f'Cannot fetch DID document from {full_url}')
	return did_doc


def parse_jwk_key(did_doc):
	jwk_key = None
	for method in did_doc.get('verificationMethod', []):
		if method['id'] == key_reference:
			if method['type'] != 'JsonWebKey2020':
				raise exceptions.InvalidDidDocument('Verification method is the wrong type')
			if (
				method['publicKeyJwk'].get('crv') != 'P-256'
				or method['publicKeyJwk'].get('kty') != 'EC'
			):
				raise exceptions.InvalidDidDocument('JWK is not valid')
			jwk_key = method['publicKeyJwk']
	return jwk_key


def create_cose_key(x, y):
	x = urlsafe_b64decode(pad_base64(x))
	y = urlsafe_b64decode(pad_base64(y))
	cose_key = EC2Key(crv=KtyEC2, x=x, y=y)
	return cose_key


def pad_base32(string):
	return _pad_base(string, 8)


def pad_base64(string):
	return _pad_base(string, 4)


def _pad_base(string, divisor):
	padding_length = ceil(len(string) / divisor) * divisor - len(string)
	return string + '=' * padding_length


def validate_verifiable_claim(vc):
	context = vc.get('@context')
	type = vc.get('type')
	version = vc.get('version')
	subject = vc.get('credentialSubject')
	if context[0] != 'https://www.w3.org/2018/credentials/v1':
		raise exceptions.InvalidVerifiableClaim('VC context is invalid')
	elif type[0] != 'VerifiableCredential' or type[1] not in PASS_TYPES:
		raise exceptions.InvalidVerifiableClaim('VC type is invalid')
	elif version != SPEC_VERSION_LONG:
		raise exceptions.InvalidVerifiableClaim('VC version is invalid')

	for prop in PASS_TYPES[type[1]]:
		if prop not in subject:
			raise exceptions.InvalidVerifiableClaim(f'VC subject missing {prop}')

	return subject


if len(sys.argv) != 2:
	LOGGER.error(f'Usage: python3 {sys.argv[0]} <qr_payload>')
	exit(1)

key = sys.argv[1]

# Make sure format matches what we expect
pattern = r'^NZCP:\/(\d+)\/(.+)$'
match = re.search(pattern, key)
if match is None:
	raise exceptions.InvalidPayload('Invalid payload')

version = match.group(1)
encoded_payload = match.group(2)
LOGGER.debug(f'Using version {version}')
if int(version) != SPEC_VERSION:
	raise exceptions.InvalidPayload('Invalid version')

try:
	decoded_payload = b32decode(pad_base32(encoded_payload))
except binascii.Error as e:
	raise exceptions.InvalidPayload('Invalid base32 payload') from e

cose_payload = Sign1Message.decode(decoded_payload)
LOGGER.debug(f'Got COSE payload {cose_payload}')

headers = cose_payload.phdr
payload = cbor2.loads(cose_payload.payload)
LOGGER.debug(f'Got CBOR payload {payload}')

# Verify headers
if not headers.get(KID) or not headers.get(Algorithm):
	raise exceptions.InvalidHeaders('Headers are missing')
if headers.get(Algorithm) != Es256:
	raise exceptions.InvalidHeaders('Algorithm does not match')

# Find all the expected headers
cwt_token_id = payload[7]
issuer = payload[1]
not_before = payload[5]
expiry = payload[4]
verifiable_claim = payload['vc']

# Validate issuer is one we trust
LOGGER.debug(f'Issued by {issuer}')
if issuer not in VALID_ISSUERS:
	raise exceptions.InvalidIssuer('Invalid issuer')

did_doc = fetch_did_document(issuer)
if did_doc is None:
	raise exceptions.InvalidDidDocument('Could not find DID document')

key_reference = f'{issuer}#{headers.get(KID).decode()}'
if key_reference not in did_doc.get('assertionMethod', []):
	raise exceptions.InvalidDidDocument('Verification method not found')

jwk_key = parse_jwk_key(did_doc)
if jwk_key is None:
	raise exceptions.InvalidDidDocument('JWK not found')

cose_payload.key = create_cose_key(jwk_key['x'], jwk_key['y'])

# Validate all of the claims
if not_before > int(time.time()):
	raise exceptions.PassNotActive('Pass not active yet')
elif expiry < int(time.time()):
	raise exceptions.PassExpired('Pass expired')
elif not cose_payload.verify_signature():
	raise exceptions.InvalidSignature('Signature cannot be validated')

# TODO: do I need to decode this and made sure its a valid UUID?
print(f'Unique ID {cwt_token_id}')

pass_subject = validate_verifiable_claim(verifiable_claim)

name = f'{pass_subject["givenName"]} {pass_subject["familyName"]}'
dob = pass_subject['dob']
print(f'Name: {name}')
print(f'DOB: {dob}')
print(f'Expires {datetime.fromtimestamp(expiry)}')
