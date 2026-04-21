package de.mtg.jlint.lints.cabf_br;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.lints.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class CrlEntryReasonCodeUnspecifiedTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void naTest() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CRLException {
        X509CRL crl = caExtension.createCRL();
        caExtension.assertLintResult(LintResult.of(Status.NA), false, new CrlEntryReasonCodeUnspecified(), crl, null);
    }

    @Test
    void passTest() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CRLException {
        X509CRL crl = createTestCRL(CRLReason.affiliationChanged);
        caExtension.assertLintResult(LintResult.of(Status.PASS), true, new CrlEntryReasonCodeUnspecified(), crl, null);
    }

    @Test
    void errorTest() throws CRLException, OperatorCreationException, IOException {
        X509CRL crl = createTestCRL(CRLReason.unspecified);
        caExtension.assertLintResult(LintResult.of(Status.ERROR), true, new CrlEntryReasonCodeUnspecified(), crl, null);
    }


    private X509CRL createTestCRL(int reasonCode) throws CRLException, OperatorCreationException, IOException {

        Date thisUpdate = Date.from(LocalDateTime.now().minusHours(1).atZone(ZoneId.systemDefault()).toInstant());
        Date nextUpdate = Date.from(LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

        Extension firstReasonCode = new Extension(Extension.reasonCode, false, CRLReason.lookup(reasonCode).toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extensions firstExtensions = new Extensions(firstReasonCode);
        Extension secondReasonCode = new Extension(Extension.reasonCode, false, CRLReason.lookup(CRLReason.superseded).getEncoded(ASN1Encoding.DER));
        Extensions secondExtensions = new Extensions(secondReasonCode);

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caExtension.getIsserDN(), thisUpdate);
        crlBuilder.setNextUpdate(nextUpdate);
        crlBuilder.addCRLEntry(BigInteger.ONE, new Date(), firstExtensions);
        crlBuilder.addCRLEntry(BigInteger.TEN, new Date(), secondExtensions);
        ContentSigner contentSigner = new JcaContentSignerBuilder(CAExtension.SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caExtension.getCaPrivateKey());
        X509CRLHolder holder = crlBuilder.build(contentSigner);

        return new JcaX509CRLConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCRL(holder);

    }

}