package de.mtg.jlint.pqc.lints;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.pqc.PQCCAExtension;
import de.mtg.jlint.pqc.util.PQCUtils;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class SlhDsaSignatureAidEncodingTest {

    @RegisterExtension
    static PQCCAExtension pqccaExtension = new PQCCAExtension();

    @Test
    void passTest() throws Exception {

        PrivateKey privateKey = pqccaExtension.getSlhdsaPrivateKey();
        PublicKey publicKey = pqccaExtension.getSlhdsaPublicKey();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(100);
        X500Name issuerDN = new X500Name("CN=JZLint CA, C=DE");
        X500Name subjectDN = new X500Name("CN=PQC Certificate, C=DE");
        AlgorithmIdentifier signatureAID = new AlgorithmIdentifier(PQCUtils.ID_ALG_SLH_DSA_128S_SHA2);

        V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                publicKey, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, null);

        X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                PQCUtils.ID_ALG_SLH_DSA_128S_SHA2.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

        pqccaExtension.assertLintResult(LintResult.of(Status.PASS), new SlhDsaSignatureAidEncoding(), certificate);
    }

    @Test
    void naTest() throws Exception {
        X509Certificate certificate = PQCCAExtension.createECCertificate();
        pqccaExtension.assertLintResult(LintResult.of(Status.NA), new SlhDsaSignatureAidEncoding(), certificate);
    }

    @Test
    void errorTest() throws Exception {

        PrivateKey privateKey = pqccaExtension.getSlhdsaPrivateKey();
        PublicKey publicKey = pqccaExtension.getSlhdsaPublicKey();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(100);
        X500Name issuerDN = new X500Name("CN=JZLint CA, C=DE");
        X500Name subjectDN = new X500Name("CN=PQC Certificate, C=DE");
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        AlgorithmIdentifier signatureAID = new AlgorithmIdentifier(PQCUtils.ID_ALG_SLH_DSA_128S_SHA2, DERNull.INSTANCE);

        V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                subjectPublicKeyInfo, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, null);

        X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                PQCUtils.ID_ALG_SLH_DSA_128S_SHA2.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

        pqccaExtension.assertLintResult(LintResult.of(Status.ERROR), new SlhDsaSignatureAidEncoding(), certificate);
    }

}
