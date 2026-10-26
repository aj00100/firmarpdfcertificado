import { PDFDocument, PDFName, PDFNumber, PDFString, PDFHexString } from 'pdf-lib';
import { extractPkcs12, patchByteRangeAndGetSignedBytes, createPAdESSignature, injectHexSignature } from './crypto-helpers';

self.onmessage = async (e: MessageEvent) => {
  const { pdfBuffer, p12Buffer, password, stampConfig } = e.data;

  try {
    self.postMessage({ status: 'progress', message: 'Desencriptando y validando certificado digital...' });

    // 1. Extract Certificate & Keys (Dual Engine PKCS#12)
    const certData = extractPkcs12(p12Buffer, password);

    // Check expiration
    const now = new Date();
    if (now > certData.notAfter) {
      throw new Error(`El certificado caducó el ${certData.notAfter.toLocaleDateString('es-ES')}.`);
    }

    self.postMessage({
      status: 'progress',
      message: `Certificado válido: ${certData.subjectName} (${certData.nif || 'Sin NIF'}). Preparando estructura PAdES...`,
    });

    // 2. Load PDF into memory
    const pdfDoc = await PDFDocument.load(pdfBuffer, { ignoreEncryption: true });

    // 3. Ensure AcroForm with SigFlags = 3 (SignaturesExist + AppendOnly)
    let acroForm = pdfDoc.catalog.get(PDFName.of('AcroForm'));
    if (!acroForm) {
      acroForm = pdfDoc.context.obj({
        Fields: [],
        SigFlags: 3,
      });
      pdfDoc.catalog.set(PDFName.of('AcroForm'), acroForm);
    } else {
      (acroForm as any).set(PDFName.of('SigFlags'), PDFNumber.of(3));
    }

    // 4. Create Signature Appearance Stream (Form XObject)
    const stampWidth = 240;
    const stampHeight = 65;
    const dateFormatted = new Date().toLocaleString('es-ES', { timeZone: 'Europe/Madrid' });

    // Stream content commands: draw navy border and crisp official Spanish text
    const streamContent = `
q
0.12 0.23 0.54 RG
1.2 w
1 1 ${stampWidth - 2} ${stampHeight - 2} re
S
0.96 0.98 1.0 rg
2 2 ${stampWidth - 4} ${stampHeight - 4} re
f
BT
/Helvetica-Bold 7 Tf
0.12 0.23 0.54 rg
8 ${stampHeight - 14} Td
(FIRMADO DIGITALMENTE) Tj
ET
BT
/Helvetica 6.5 Tf
0.1 0.1 0.1 rg
8 ${stampHeight - 24} Td
(Firmante: ${certData.subjectName.replace(/[()]/g, '')}) Tj
ET
BT
/Helvetica 6.5 Tf
0.1 0.1 0.1 rg
8 ${stampHeight - 34} Td
(NIF / Documento: ${certData.nif || 'No identificado'}) Tj
ET
BT
/Helvetica 6 Tf
0.3 0.3 0.3 rg
8 ${stampHeight - 44} Td
(Fecha: ${dateFormatted} CET/CEST) Tj
ET
BT
/Helvetica-Oblique 5.5 Tf
0.2 0.4 0.2 rg
8 ${stampHeight - 54} Td
(Validez legal: Reglamento UE 910/2014 eIDAS y Ley 6/2020) Tj
ET
Q
`.trim();

    const appearanceStream = pdfDoc.context.flateStream(streamContent, {
      Type: 'XObject',
      Subtype: 'Form',
      BBox: [0, 0, stampWidth, stampHeight],
      Resources: {
        Font: {
          'Helvetica-Bold': { Type: 'Font', Subtype: 'Type1', BaseFont: 'Helvetica-Bold' },
          Helvetica: { Type: 'Font', Subtype: 'Type1', BaseFont: 'Helvetica' },
          'Helvetica-Oblique': { Type: 'Font', Subtype: 'Type1', BaseFont: 'Helvetica-Oblique' },
        },
      },
    });
    const appearanceStreamRef = pdfDoc.context.register(appearanceStream);

    // 5. Create /Sig dictionary with fixed-width 10-digit placeholders
    const sigDict = pdfDoc.context.obj({
      Type: 'Sig',
      Filter: 'Adobe.PPKLite',
      SubFilter: 'ETSI.CAdES.detached',
      ByteRange: [
        PDFNumber.of(0),
        PDFNumber.of(1000000000), // 10-digit placeholder: 0000000000
        PDFNumber.of(1000000000),
        PDFNumber.of(1000000000),
      ],
      Contents: PDFHexString.of('0'.repeat(16384)), // 8192 bytes allocated
      Reason: PDFString.of('Firma digital criptográfica PAdES con certificado FNMT'),
      M: PDFString.fromDate(new Date()),
      ContactInfo: PDFString.of('https://firmarpdfcertificado.com'),
    });
    const sigDictRef = pdfDoc.context.register(sigDict);

    // 6. Attach /Widget Annotation linked to /Sig and Appearance Stream
    const pages = pdfDoc.getPages();
    const pageIndex = stampConfig?.pageIndex ?? pages.length - 1;
    const targetPage = pages[Math.max(0, Math.min(pageIndex, pages.length - 1))];
    const { width: pageWidth, height: pageHeight } = targetPage.getSize();

    const posX = stampConfig?.x ?? Math.max(20, pageWidth - stampWidth - 25);
    const posY = stampConfig?.y ?? 25;

    const widget = pdfDoc.context.obj({
      Type: 'Annot',
      Subtype: 'Widget',
      FT: 'Sig',
      Rect: [posX, posY, posX + stampWidth, posY + stampHeight],
      V: sigDictRef,
      P: targetPage.ref,
      F: 132, // Print (4) + Locked (128)
      AP: pdfDoc.context.obj({
        N: appearanceStreamRef,
      }),
    });
    const widgetRef = pdfDoc.context.register(widget);

    targetPage.node.addAnnot(widgetRef);
    (acroForm as any).get(PDFName.of('Fields')).push(widgetRef);

    // 7. SINGLE SAVE with useObjectStreams: false (Strictly avoid re-serialization)
    self.postMessage({ status: 'progress', message: 'Serializando documento y calculando offsets...' });
    const savedBytes = await pdfDoc.save({ useObjectStreams: false });

    // 8. Direct in-place binary ByteRange calculation
    const { patchedPdf, signedBytes, contentsStart, contentsEnd } = patchByteRangeAndGetSignedBytes(savedBytes);

    // 9. Generate ETSI PAdES-B-B Signature (with ESS signing-certificate-v2)
    self.postMessage({ status: 'progress', message: 'Generando firma criptográfica PAdES-B-B (SHA-256/RSA)...' });
    const hexSignature = createPAdESSignature(signedBytes, certData);

    // 10. Direct in-place binary injection into /Contents
    const finalSignedPdf = injectHexSignature(patchedPdf, contentsStart, contentsEnd, hexSignature);

    self.postMessage({
      status: 'done',
      signedPdf: finalSignedPdf,
      signerName: certData.subjectName,
      nif: certData.nif,
      issuer: certData.issuer,
    });
  } catch (err: any) {
    self.postMessage({
      status: 'error',
      error: err.message || 'Error desconocido durante la firma del PDF.',
    });
  }
};
