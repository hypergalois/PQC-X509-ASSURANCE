package de.mtg.jlint.lints.rfc;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
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

class CrlAiaExtensionNonCriticalTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void naTest() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CRLException {
        X509CRL crl = caExtension.createCRL();
        caExtension.assertLintResult(LintResult.of(Status.NA), false, new CrlAiaExtensionNonCritical(), crl, null);
    }

    @Test
    void passTest() throws OperatorCreationException, CRLException, IOException {
        X509CRL crl = createTestCRL(false);
        caExtension.assertLintResult(LintResult.of(Status.PASS), true, new CrlAiaExtensionNonCritical(), crl, null);
    }

    @Test
    void errorTest() throws CRLException, OperatorCreationException, IOException {
        X509CRL crl = createTestCRL(true);
        caExtension.assertLintResult(LintResult.of(Status.ERROR), true, new CrlAiaExtensionNonCritical(), crl, null);
    }

    private X509CRL createTestCRL(boolean critical) throws CRLException, OperatorCreationException, IOException {

        Date thisUpdate = Date.from(LocalDateTime.now().minusHours(1).atZone(ZoneId.systemDefault()).toInstant());
        Date nextUpdate = Date.from(LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caExtension.getIsserDN(), thisUpdate);
        crlBuilder.setNextUpdate(nextUpdate);

        AccessDescription accessDescription = new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.com"));
        AuthorityInformationAccess aia = new AuthorityInformationAccess(accessDescription);
        crlBuilder.addExtension(new Extension(Extension.authorityInfoAccess, critical, aia.toASN1Primitive().getEncoded(ASN1Encoding.DER)));

        ContentSigner contentSigner = new JcaContentSignerBuilder(CAExtension.SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caExtension.getCaPrivateKey());
        X509CRLHolder holder = crlBuilder.build(contentSigner);

        return new JcaX509CRLConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCRL(holder);

    }

}