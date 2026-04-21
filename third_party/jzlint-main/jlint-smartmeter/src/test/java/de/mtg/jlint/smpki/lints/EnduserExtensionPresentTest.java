package de.mtg.jlint.smpki.lints;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.smpki.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class EnduserExtensionPresentTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    private SmpkiEnduserExtensionPresent lint = new SmpkiEnduserExtensionPresent();

    @Test
    void passTest() throws Exception {

        {
            var certificate = caExtension.createEnduserCertificate("CN=ORG.EMT.EXT, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            caExtension.assertLintResult(LintResult.of(Status.PASS), lint, certificate, true, "");
        }

        {
            var certificate = caExtension.createEnduserCertificate("CN=ORG.EMT, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            caExtension.assertLintResult(LintResult.of(Status.PASS), lint, certificate, true, "");
        }

        {
            var certificate = caExtension.createEnduserCertificate("CN=ORG.GWA, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            caExtension.assertLintResult(LintResult.of(Status.PASS), lint, certificate, true, "");
        }
        {
            var certificate = caExtension.createEnduserCertificate("CN=ORG.GWA.EXT, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            caExtension.assertLintResult(LintResult.of(Status.PASS), lint, certificate, true, "");
        }
    }

    @Test
    void errorTest() throws Exception {
        var certificate =
                createWrongCertificate("CN=ORG.GWA.EXT, O=SM-PKI-DE, SERIALNUMBER=1, C=DE", caExtension.getCaPublicKey(), caExtension.getIsserDN(),
                        caExtension.getCaPrivateKey());
        caExtension.assertLintResult(LintResult.of(Status.ERROR), lint, certificate, true,
                "Certificate is an SM-PKI enduser certificate, but does not have the CRL distribution points extension.");
    }

    @Test
    void notApplicableTest() throws Exception {
        var certificate = caExtension.getCaCertificate();
        caExtension.assertLintResult(LintResult.of(Status.NA), lint, certificate, false, "");
    }


    public X509Certificate createWrongCertificate(String subjectDN, PublicKey caPublicKey, X500Name issuerDN, PrivateKey caPrivateKey)
            throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException {

        var serialNumber = new BigInteger(96, new Random());
        var notBefore = ZonedDateTime.of(2025, 7, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
        var notBeforeDate = Date.from(notBefore.toInstant());
        var noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        var keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        var keyPair = keyPairGenerator.generateKeyPair();
        var publicKey = keyPair.getPublic();
        var subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        var certificateSubjectDN = new X500Name(subjectDN);

        var aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        var ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        var akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        var skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        var keyUsage = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature);
        var ku = new Extension(Extension.keyUsage, true, keyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        var bc = new BasicConstraints(false);
        var basicConstraints = new Extension(Extension.basicConstraints, true, bc.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        var generalName = new GeneralName(GeneralName.rfc822Name, String.format("test@example.com"));
        var generalNames = new GeneralNames(generalName);
        var encoded = generalNames.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        var ian = new Extension(Extension.issuerAlternativeName, false, encoded);
        var san = new Extension(Extension.subjectAlternativeName, false, encoded);

        var url = new DERIA5String("https://crldp.example.com/crl");
        var generalNameArray = new GeneralName[1];
        generalNameArray[0] = new GeneralName(6, url);
        var crldpGeneralNames = new GeneralNames(generalNameArray);
        var distributionPointName = new DistributionPointName(crldpGeneralNames);
        var distributionPoints = new DistributionPoint[1];
        distributionPoints[0] = new DistributionPoint(distributionPointName, null, null);
        var crlDistributionPoint = new CRLDistPoint(distributionPoints);
        var crldp = new Extension(Extension.cRLDistributionPoints, false, crlDistributionPoint.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension certificatePolicies = CAExtension.getCertificatePolicies("0.4.0.127.0.7.3.4.1.1.1");

        var certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, certificateSubjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(ku);
        certificateBuilder.addExtension(basicConstraints);
        certificateBuilder.addExtension(ian);
        certificateBuilder.addExtension(san);
        certificateBuilder.addExtension(certificatePolicies);
        //certificateBuilder.addExtension(crldp);
        var contentSigner =
                new JcaContentSignerBuilder(CAExtension.SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(caPrivateKey);
        var x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

}
