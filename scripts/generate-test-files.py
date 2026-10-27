#!/usr/bin/env python3
"""
Generador de archivos de prueba (PDF y Certificado PKCS#12) para FirmarPDFCertificado.com
Crea:
  - test_document.pdf
  - test_certificate.p12 (Contraseña: 1234)
  - test_certificate.pfx (Contraseña: 1234)
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption

def generate_certificate(output_dir="."):
    print("🔑 Generando clave privada RSA 2048-bit y certificado X.509 de prueba...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FirmarPDFCertificado Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "JUAN PEREZ GARCIA (TEST)"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "12345678Z"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"Certificado de Prueba - Juan Perez",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(b"1234")
    )

    p12_path = os.path.join(output_dir, "test_certificate.p12")
    pfx_path = os.path.join(output_dir, "test_certificate.pfx")
    with open(p12_path, "wb") as f:
        f.write(p12_data)
    with open(pfx_path, "wb") as f:
        f.write(p12_data)
    print(f"✅ Certificado guardado en: {p12_path} y {pfx_path} (Contraseña: 1234)")


def generate_pdf(output_dir="."):
    print("📄 Generando PDF de prueba...")
    content = """BT
/F1 22 Tf
50 740 Td
(DOCUMENTO DE PRUEBA PARA FIRMA DIGITAL) Tj
0 -35 Td
/F1 12 Tf
(FirmarPDFCertificado.com - Entorno de Validacion y Pruebas) Tj
0 -30 Td
/F2 11 Tf
(Este documento PDF ha sido generado para verificar el funcionamiento de la) Tj
0 -18 Td
(plataforma de firma digital en el navegador con certificado software.) Tj
0 -35 Td
/F1 13 Tf
(DATOS DEL DOCUMENTO:) Tj
0 -24 Td
/F2 10 Tf
(- Codigo de Referencia: EXP-2026-TEST-0099) Tj
0 -18 Td
(- Emisor: FirmarPDFCertificado.com) Tj
0 -18 Td
(- Titular autorizado: Juan Perez Garcia (NIF 12345678Z)) Tj
0 -18 Td
(- Formato de firma esperado: PAdES-B-B (ETSI EN 319 142-1)) Tj
0 -18 Td
(- Seguridad: 100% en memoria local (RAM) sin envio de datos al servidor) Tj
0 -45 Td
/F1 12 Tf
(INSTRUCCIONES DE USO:) Tj
0 -22 Td
/F2 10 Tf
(1. Accede a https://firmarpdfcertificado.com) Tj
0 -18 Td
(2. Arrastra este archivo PDF en la casilla 1) Tj
0 -18 Td
(3. Arrastra el certificado 'test_certificate.p12' en la casilla 2) Tj
0 -18 Td
(4. Introduce la contrasena: 1234) Tj
0 -18 Td
(5. Pulsa en 'Firmar PDF Ahora' y descarga tu documento firmado) Tj
0 -60 Td
/F1 11 Tf
(Espacio para estampado de firma visible:) Tj
ET
0.93 0.95 0.98 rg
50 200 512 110 re
f
0.2 0.4 0.8 RG
1.5 w
50 200 512 110 re
S
BT
/F1 11 Tf
70 270 Td
(RECUADRO DE FIRMA DIGITAL CON CERTIFICADO) Tj
0 -20 Td
/F2 9 Tf
(Firmado digitalmente por: JUAN PEREZ GARCIA (TEST) - NIF 12345678Z) Tj
0 -15 Td
(Fecha y Hora: 27/10/2026 | Validez legal segun Reglamento eIDAS) Tj
ET
"""
    stream_bytes = content.encode("latin1")
    stream_len = len(stream_bytes)

    pdf = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page
   /Parent 2 0 R
   /MediaBox [0 0 612 792]
   /Contents 4 0 R
   /Resources <<
     /Font <<
       /F1 <<
         /Type /Font
         /Subtype /Type1
         /BaseFont /Helvetica-Bold
       >>
       /F2 <<
         /Type /Font
         /Subtype /Type1
         /BaseFont /Helvetica
       >>
     >>
   >>
>>
endobj
4 0 obj
<< /Length {stream_len} >>
stream
{content}endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000378 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
{378 + stream_len + 50}
%%EOF
"""
    pdf_path = os.path.join(output_dir, "test_document.pdf")
    with open(pdf_path, "wb") as f:
        f.write(pdf.encode("latin1"))
    print(f"✅ Documento PDF guardado en: {pdf_path}")


if __name__ == "__main__":
    generate_certificate()
    generate_pdf()
    print("\n🎉 ¡Archivos de prueba generados correctamente!")
