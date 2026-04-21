package de.mtg.jlint.lints.rfc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.lints.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class IssuerCommonNameMaxLengthTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void naTest() throws Exception {
        X509Certificate certificate = createNACertificate(caExtension);
        caExtension.assertLintResult(LintResult.of(Status.NA), new IssuerCommonNameMaxLength(), certificate);
    }

    @Test
    void passTest() throws Exception {
        X509Certificate certificate = createMaximumLengthCertificate(caExtension);
        caExtension.assertLintResult(LintResult.of(Status.PASS), new IssuerCommonNameMaxLength(), certificate);
    }

    @Test
    void errorTest() throws Exception {
        X509Certificate certificate = createExceedingMaximumLengthCertificate(caExtension);
        caExtension.assertLintResult(LintResult.of(Status.ERROR), new IssuerCommonNameMaxLength(), certificate);
    }

    protected static X509Certificate createNACertificate(CAExtension caExtension) throws OperatorCreationException, IOException, NoSuchAlgorithmException, CertificateException {
        return createMaximumLengthCertificate(caExtension, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, true);
    }

    protected static X509Certificate createMaximumLengthCertificate(CAExtension caExtension) throws OperatorCreationException, IOException, NoSuchAlgorithmException, CertificateException {

        int maxCN = 64;
        int maxSerialNumber = 64;
        int maxEmail = 255;
        int maxGivenName = 32768;
        int maxPostalCode = 17;
        int maxStreet = 128;
        int maxSurname = 32768;
        int maxLocality = 128;
        int maxO = 64;
        int maxOU = 64;
        int maxState = 128;

        return createMaximumLengthCertificate(caExtension, maxCN, maxSerialNumber, maxEmail, maxGivenName,
                maxPostalCode, maxStreet, maxSurname, maxLocality, maxO, maxOU, maxState, false);

    }

    protected static X509Certificate createExceedingMaximumLengthCertificate(CAExtension caExtension) throws OperatorCreationException, IOException, NoSuchAlgorithmException, CertificateException {

        int maxCN = 65;
        int maxSerialNumber = 65;
        int maxEmail = 256;
        int maxGivenName = 32769;
        int maxPostalCode = 18;
        int maxStreet = 129;
        int maxSurname = 32769;
        int maxLocality = 129;
        int maxO = 65;
        int maxOU = 65;
        int maxState = 129;

        return createMaximumLengthCertificate(caExtension, maxCN, maxSerialNumber, maxEmail, maxGivenName,
                maxPostalCode, maxStreet, maxSurname, maxLocality, maxO, maxOU, maxState, false);

    }

    public static X509Certificate createMaximumLengthCertificate(CAExtension caExtension, int maxCN, int maxSerialNumber,
                                                           int maxEmail, int maxGivenName, int maxPostalCode,
                                                           int maxStreet, int maxSurname, int maxLocality,
                                                           int maxO, int maxOU, int maxState,
                                                           boolean createNotApplicable)
            throws OperatorCreationException, IOException, NoSuchAlgorithmException, CertificateException {


        List<RDN> rdns = new ArrayList<>();

        if (createNotApplicable) {
            rdns.add(new RDN(BCStyle.DC, new DERUTF8String(Stream.generate(() -> "a").limit(10).collect(Collectors.joining()))));
        } else {
            rdns.add(new RDN(BCStyle.CN, new DERUTF8String(Stream.generate(() -> "a").limit(maxCN).collect(Collectors.joining()))));
            rdns.add(new RDN(BCStyle.SERIALNUMBER, new DERUTF8String(Stream.generate(() -> "a").limit(maxSerialNumber).collect(Collectors.joining()))));
            rdns.add(new RDN(BCStyle.EmailAddress, new DERIA5String(Stream.generate(() -> "a").limit(maxEmail).collect(Collectors.joining()))));
            rdns.add(new RDN(BCStyle.GIVENNAME, new DERUTF8String(Stream.generate(() -> "a").limit(maxGivenName).collect(Collectors.joining()))));
            rdns.add(new RDN(BCStyle.POSTAL_CODE, new DERUTF8String(Stream.generate(() -> "a").limit(maxPostalCode).collect(Collectors.joining()))));
            rdns.add(new RDN(BCStyle.STREET, new DERUTF8String(Stream.generate(() -> "a").limit(maxStreet).collect(Collectors.joining()))));
            rdns.add(new RDN(BCStyle.SURNAME, new DERUTF8String(Stream.generate(() -> "a").limit(maxSurname).collect(Collectors.joining()))));
            rdns.add(new RDN(X509ObjectIdentifiers.localityName, new DERUTF8String(Stream.generate(() -> "a").limit(maxLocality).collect(Collectors.joining()))));
            rdns.add(new RDN(X509ObjectIdentifiers.organization, new DERUTF8String(Stream.generate(() -> "a").limit(maxO).collect(Collectors.joining()))));
            rdns.add(new RDN(X509ObjectIdentifiers.organizationalUnitName, new DERUTF8String(Stream.generate(() -> "a").limit(maxOU).collect(Collectors.joining()))));
            rdns.add(new RDN(X509ObjectIdentifiers.stateOrProvinceName, new DERUTF8String(Stream.generate(() -> "a").limit(maxState).collect(Collectors.joining()))));
        }

        X500Name name = new X500Name(rdns.toArray(new RDN[0]));

        PublicKey caPublicKey = caExtension.getCaPublicKey();
        PrivateKey caPrivateKey = caExtension.getCaPrivateKey();

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(caPublicKey.getEncoded());
        BigInteger serialNumber = new BigInteger(96, new Random());
        Date notBefore = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        Date noteAfter = Date.from(LocalDateTime.now().plusYears(5).atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(name, serialNumber, notBefore, noteAfter, name, subjectPublicKeyInfo);

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(caPublicKey);

        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        BasicConstraints bc = new BasicConstraints(true);
        Extension basicConstraints = new Extension(Extension.basicConstraints, true, bc.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(basicConstraints);

        ContentSigner contentSigner = new JcaContentSignerBuilder(CAExtension.SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

}
