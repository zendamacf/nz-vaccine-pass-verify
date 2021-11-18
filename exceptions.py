class VaccinePassInvalid(Exception):
	pass


class InvalidPayload(VaccinePassInvalid):
	pass


class InvalidHeaders(VaccinePassInvalid):
	pass


class InvalidIssuer(VaccinePassInvalid):
	pass


class InvalidDidDocument(VaccinePassInvalid):
	pass


class PassNotActive(VaccinePassInvalid):
	pass


class PassExpired(VaccinePassInvalid):
	pass


class InvalidSignature(VaccinePassInvalid):
	pass


class InvalidVerifiableClaim(VaccinePassInvalid):
	pass
