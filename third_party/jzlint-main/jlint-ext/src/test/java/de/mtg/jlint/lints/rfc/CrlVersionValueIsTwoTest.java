package de.mtg.jlint.lints.rfc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.lints.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class CrlVersionValueIsTwoTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void passTest() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CRLException {
        X509CRL crl = caExtension.createCRL();
        caExtension.assertLintResult(LintResult.of(Status.PASS), true, new CrlVersionValueIsTwo(), crl, null);
    }

    @Test
    void errorTest() throws NoSuchAlgorithmException, IOException, NoSuchProviderException, CertificateException, SignatureException, InvalidKeyException, CRLException {
        X509CRL crl = createWrongCRL();
        caExtension.assertLintResult(LintResult.of(Status.ERROR), true, new CrlVersionValueIsTwo(), crl, "CRL is not version 2 but it is version 1");
    }

    private X509CRL createWrongCRL() throws NoSuchAlgorithmException, IOException, CRLException, NoSuchProviderException, InvalidKeyException, SignatureException, CertificateException {

        AlgorithmIdentifier signatureAID = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
        Date thisUpdate = Date.from(LocalDateTime.now().minusHours(1).atZone(ZoneId.systemDefault()).toInstant());
        Date nextUpdate = Date.from(LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

        ASN1EncodableVector tBSCertListVector = new ASN1EncodableVector();
        tBSCertListVector.add(new ASN1Integer(0));
        tBSCertListVector.add(signatureAID);
        tBSCertListVector.add(caExtension.getIsserDN());
        tBSCertListVector.add(new ASN1GeneralizedTime(thisUpdate));
        tBSCertListVector.add(new ASN1GeneralizedTime(nextUpdate));
        tBSCertListVector.add(new DERSequence());

        ASN1EncodableVector extensions = new ASN1EncodableVector();
        extensions.add(new Extension(Extension.cRLNumber, false, new ASN1Integer(1).getEncoded(ASN1Encoding.DER)));
        tBSCertListVector.add(new DERTaggedObject(true, 0, new DERSequence(extensions)));

        DERSequence tBSCertList = new DERSequence(tBSCertListVector);

        Signature jcaSignature = Signature.getInstance(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), BouncyCastleProvider.PROVIDER_NAME);
        jcaSignature.initSign(caExtension.getCaPrivateKey());
        jcaSignature.update(tBSCertList.getEncoded(ASN1Encoding.DER));
        byte[] signature = jcaSignature.sign();

        ASN1EncodableVector certificateListVector = new ASN1EncodableVector();
        certificateListVector.add(tBSCertList);
        certificateListVector.add(signatureAID);
        certificateListVector.add(new DERBitString(signature));

        byte[] rawCRL = new DERSequence(certificateListVector).getEncoded(ASN1Encoding.DER);

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

        try (ByteArrayInputStream bais = new ByteArrayInputStream(rawCRL)) {
            return (X509CRL) cf.generateCRL(bais);
        }
    }

}