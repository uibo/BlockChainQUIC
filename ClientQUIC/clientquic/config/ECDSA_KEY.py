from coincurve import PrivateKey

STATIC_PRIVATE = [
    PrivateKey(bytes.fromhex('48c3222ebbbb3f2ca0a121af3eb42c1b331a94b1da6fd8dac97e90405e19a57d')),
    PrivateKey(bytes.fromhex('8e0feade80f19b69e5c9f77f359decbfae3fe92780f19eea32c71bb2bdd1414f')),
]

STATIC_PUBLIC = [
    STATIC_PRIVATE[0].public_key.format(compressed=False),
    STATIC_PRIVATE[1].public_key.format(compressed=False),
]