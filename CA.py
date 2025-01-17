from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Generate CA private key
ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Save the CA private key to a file
with open("ca_private_key.pem", "wb") as key_file:
    key_file.write(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# Generate the CA's self-signed certificate
ca_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyProject CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, "MyProject Root CA"),
])
ca_certificate = (
    x509.CertificateBuilder()
    .subject_name(ca_subject)
    .issuer_name(ca_subject)  # Self-signed
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(private_key=ca_key, algorithm=hashes.SHA256())
)

# Save the CA certificate to a file
with open("ca_certificate.pem", "wb") as cert_file:
    cert_file.write(ca_certificate.public_bytes(serialization.Encoding.PEM))

print("CA private key and certificate generated!")


def generate_server_certificate(common_name, ca_key, ca_certificate):
    # Generate server private key
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save the server private key
    with open("server_private_key.pem", "wb") as key_file:
        key_file.write(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyProject Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        .sign(server_key, hashes.SHA256())
    )

    # Sign the server certificate with the CA
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        # Valid for 1 year
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # Save the server certificate
    with open("server_certificate.pem", "wb") as cert_file:
        cert_file.write(server_certificate.public_bytes(
            serialization.Encoding.PEM))

    print("Server private key and certificate generated!")


# Load CA private key and certificate
with open("ca_private_key.pem", "rb") as key_file:
    ca_key = serialization.load_pem_private_key(key_file.read(), password=None)

with open("ca_certificate.pem", "rb") as cert_file:
    ca_certificate = x509.load_pem_x509_certificate(cert_file.read())

# Generate a certificate for the server
generate_server_certificate("myserver.local", ca_key, ca_certificate)


def sign_document(file_path, ca_key):
    with open(file_path, "rb") as file:
        file_data = file.read()

    signature = ca_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    with open(file_path + ".sig", "wb") as sig_file:
        sig_file.write(signature)

    print(f"Document signed: {file_path}.sig")


def verify_signature(file_path, signature_path, public_key):
    with open(file_path, "rb") as file:
        file_data = file.read()

    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()

    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("Signature is valid!")
    except Exception as e:
        print(f"Signature verification failed: {e}")
