"""RSA-OAEP Key Exchange Module.

Implements secure key establishment using RSA with OAEP padding
and SHA-256 for symmetric key wrapping and unwrapping.
"""

from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class RSAKeyExchangeServer:
    """Server-side handler for RSA key pair generation, loading and public key distribution."""

    DEFAULT_KEY_SIZE = 2048
    PUBLIC_EXPONENT = 65537

    def __init__(self, private_key: Optional[rsa.RSAPrivateKey] = None) -> None:
        """Initialize the server with an optional existing private key, or generate a new one."""
        if private_key is not None:
            self._private_key = private_key
        else:
            self._private_key = self.generate_key_pair(self.DEFAULT_KEY_SIZE)

    @classmethod
    def generate_key_pair(cls, key_size: int = DEFAULT_KEY_SIZE) -> rsa.RSAPrivateKey:
        """Generate a new RSA private key of the given bit size (minimum 2048 bits)."""
        if key_size < 2048:
            raise ValueError("RSA key size must be at least 2048 bits for cryptographic security.")
        return rsa.generate_private_key(
            public_exponent=cls.PUBLIC_EXPONENT,
            key_size=key_size,
        )

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        """Return the server private key instance."""
        return self._private_key

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        """Return the server public key instance."""
        return self._private_key.public_key()

    def export_public_key_pem(self) -> bytes:
        """Export the public key in PEM format (SubjectPublicKeyInfo)."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def export_private_key_pem(self, password: Optional[bytes] = None) -> bytes:
        """Export the private key in PEM format (PKCS#8), optionally encrypted with a password."""
        encryption_algorithm: serialization.KeySerializationEncryption
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encryption_algorithm = serialization.NoEncryption()

        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )

    @classmethod
    def from_private_key_pem(cls, pem_bytes: bytes, password: Optional[bytes] = None) -> "RSAKeyExchangeServer":
        """Load an RSAKeyExchangeServer instance from PEM encoded private key bytes."""
        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=password,
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("Loaded key is not an RSA private key.")
        return cls(private_key=private_key)

