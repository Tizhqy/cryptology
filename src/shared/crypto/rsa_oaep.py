"""RSA-OAEP Key Exchange Module.

Implements secure key establishment using RSA with OAEP padding
and SHA-256 for symmetric key wrapping and unwrapping.
"""

import os
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


class RSAKeyExchangeClient:
    """Client-side handler for wrapping symmetric AES keys using RSA-OAEP with SHA-256."""

    AES_128_KEY_SIZE = 16  # 128-bit key in bytes

    def __init__(self, server_public_key: rsa.RSAPublicKey) -> None:
        """Initialize client with the server's RSA public key."""
        if not isinstance(server_public_key, rsa.RSAPublicKey):
            raise TypeError("server_public_key must be an instance of RSAPublicKey.")
        self._server_public_key = server_public_key

    @classmethod
    def from_public_key_pem(cls, pem_bytes: bytes) -> "RSAKeyExchangeClient":
        """Construct client instance by loading server public key from PEM bytes."""
        public_key = serialization.load_pem_public_key(pem_bytes)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("Loaded public key is not an RSA public key.")
        return cls(server_public_key=public_key)

    @classmethod
    def generate_aes_key(cls, key_size: int = AES_128_KEY_SIZE) -> bytes:
        """Generate cryptographically secure random bytes for AES key."""
        if key_size not in (16, 24, 32):
            raise ValueError(f"Invalid AES key size: {key_size} bytes. Must be 16, 24, or 32.")
        return os.urandom(key_size)

    def wrap_aes_key(self, aes_key: bytes) -> bytes:
        """Wrap (encrypt) the provided AES key using RSA-OAEP with SHA-256 and MGF1(SHA-256).
        
        Args:
            aes_key: Symmetric AES key bytes (typically 16 bytes for AES-128).
            
        Returns:
            RSA-OAEP encrypted ciphertext bytes.
        """
        if not isinstance(aes_key, bytes):
            raise TypeError("aes_key must be bytes.")
        if len(aes_key) not in (16, 24, 32):
            raise ValueError("aes_key length must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.")

        cipher_wrapped_key = self._server_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return cipher_wrapped_key

    def generate_and_wrap_key(self, key_size: int = AES_128_KEY_SIZE) -> Tuple[bytes, bytes]:
        """Generate a fresh AES key and wrap it with server public key.
        
        Returns:
            Tuple of (raw_aes_key, encrypted_wrapped_key)
        """
        raw_key = self.generate_aes_key(key_size=key_size)
        wrapped_key = self.wrap_aes_key(raw_key)
        return raw_key, wrapped_key


