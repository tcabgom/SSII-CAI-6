from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

# Generar una clave privada RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,  # Longitud de la clave de al menos 4096 bits como requerido
    backend=default_backend()
)

# Crear una solicitud de firma de certificado (CSR) para un servidor web Apache
csr = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Sevilla"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sevilla"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),  # Nombre de dominio del servidor
    ])
).add_extension(
    x509.SubjectAlternativeName([
        x509.DNSName(u"example.com"),  # Nombre de dominio del servidor
        x509.DNSName(u"www.example.com"),  # Otros nombres de dominio, si es necesario
    ]),
    critical=False,
).sign(private_key, hashes.SHA256(), default_backend())

# Serializar CSR en formato PEM
csr_pem = csr.public_bytes(serialization.Encoding.PEM)

# Escribir CSR en un archivo
with open("apache-server.csr", "wb") as csr_file:
    csr_file.write(csr_pem)

print("Solicitud de firma de certificado (CSR) para servidor Apache generada con éxito.")
