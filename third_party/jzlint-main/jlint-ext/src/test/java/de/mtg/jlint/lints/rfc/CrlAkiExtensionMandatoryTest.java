package de.mtg.jlint.lints.rfc;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

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

class CrlAkiExtensionMandatoryTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void passTest() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CRLException {
        X509CRL crl = caExtension.createCRL();
        caExtension.assertLintResult(LintResult.of(Status.PASS), true, new CrlAkiExtensionMandatory(), crl, null);
    }

    @Test
    void errorTest() throws CRLException, OperatorCreationException {
        X509CRL crl = createWrongCRL();
        caExtension.assertLintResult(LintResult.of(Status.ERROR), true, new CrlAkiExtensionMandatory(), crl, null);
    }

    private X509CRL createWrongCRL() throws CRLException, OperatorCreationException {

        Date thisUpdate = Date.from(LocalDateTime.now().minusHours(1).atZone(ZoneId.systemDefault()).toInstant());
        Date nextUpdate = Date.from(LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caExtension.getIsserDN(), thisUpdate);
        crlBuilder.setNextUpdate(nextUpdate);
        ContentSigner contentSigner = new JcaContentSignerBuilder(CAExtension.SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caExtension.getCaPrivateKey());
        X509CRLHolder holder = crlBuilder.build(contentSigner);

        return new JcaX509CRLConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCRL(holder);

    }
}