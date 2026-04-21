package de.mtg.jzlint.utils;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.util.encoders.Base64;

public final class ASN1CertificateUtils {

    public static final int VALIDITY_POSITION_V2_V3 = 4;
    public static final int SERIAL_NUMBER_POSITION_V2_V3 = 1;
    public static final int SUBJECTPUBLICKEYINFO_POSITION_V2_V3 = 6;
    public static final int SUBJECT_POSITION_V2_V3 = 5;
    public static final int ISSUER_POSITION_V2_V3 = 3;
    public static final int SIGNATURE_POSITION_V2_V3 = 2;
    public static final int TBS_CERTIFICATE_POSITION = 0;

    private ASN1CertificateUtils() {
        // empty
    }

    public static ASN1Sequence getCertificateAsSequence(X509Certificate certificate) throws CertificateEncodingException {
        return ASN1Sequence.getInstance(certificate.getEncoded());
    }

    public static ASN1Sequence getTBSCertificate(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence asn1Certificate = getCertificateAsSequence(certificate);
        return (ASN1Sequence) asn1Certificate.getObjectAt(TBS_CERTIFICATE_POSITION);
    }

    public static ASN1Sequence getValidity(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence tbsCertificate = getTBSCertificate(certificate);
        if (!isVersionEncoded(tbsCertificate)) {
            return (ASN1Sequence) tbsCertificate.getObjectAt(VALIDITY_POSITION_V2_V3 - 1);
        }

        return (ASN1Sequence) tbsCertificate.getObjectAt(VALIDITY_POSITION_V2_V3);
    }

    public static ASN1Encodable getNotBefore(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence validity = getValidity(certificate);
        return validity.getObjectAt(0);
    }

    public static ASN1Encodable getNotAfter(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence validity = getValidity(certificate);
        return validity.getObjectAt(1);
    }

    public static boolean notBeforeIsGeneralizedTime(X509Certificate certificate) throws CertificateEncodingException, IOException {
        ASN1Encodable notBefore = getNotBefore(certificate);
        return notBefore.toASN1Primitive().getEncoded(ASN1Encoding.DER)[0] == 24;
    }

    public static boolean notBeforeIsUTCTime(X509Certificate certificate) throws CertificateEncodingException, IOException {
        ASN1Encodable notBefore = getNotBefore(certificate);
        return notBefore.toASN1Primitive().getEncoded(ASN1Encoding.DER)[0] == 23;
    }

    public static boolean notAfterIsGeneralizedTime(X509Certificate certificate) throws CertificateEncodingException, IOException {
        ASN1Encodable notBefore = getNotAfter(certificate);
        return notBefore.toASN1Primitive().getEncoded(ASN1Encoding.DER)[0] == 24;
    }

    public static boolean notAfterIsUTCTime(X509Certificate certificate) throws CertificateEncodingException, IOException {
        ASN1Encodable notBefore = getNotAfter(certificate);
        return notBefore.toASN1Primitive().getEncoded(ASN1Encoding.DER)[0] == 23;
    }

    public static boolean generalizedTimeHasFractionSeconds(ASN1GeneralizedTime generalizedTime) {
        String time = generalizedTime.getTimeString();
        // format without fraction seconds is
        // 19700101000000Z
        return time.length() > 15;
    }

    public static boolean generalizedTimeHasNotSeconds(ASN1GeneralizedTime generalizedTime) {
        String time = generalizedTime.getTimeString();
        // format with seconds is
        // 19700101000000Z
        Pattern pattern = Pattern.compile("\\d{14}Z");
        Matcher matcher = pattern.matcher(time);
        return !matcher.matches();
    }

    public static boolean isZulu(ASN1GeneralizedTime generalizedTime) throws IOException {
        byte[] encodedTime = generalizedTime.getEncoded(ASN1Encoding.DER);
        // 5a hex is 90 decimal, 5a is Z in ASCII
        return encodedTime[encodedTime.length - 1] == 90;
    }

    public static ASN1Integer getSerialNumber(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence tbsCertificate = getTBSCertificate(certificate);
        if (!isVersionEncoded(tbsCertificate)) {
            return (ASN1Integer) tbsCertificate.getObjectAt(SERIAL_NUMBER_POSITION_V2_V3 - 1);
        }
        return (ASN1Integer) tbsCertificate.getObjectAt(SERIAL_NUMBER_POSITION_V2_V3);
    }

    public static ASN1Sequence getPublicKey(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence tbsCertificate = getTBSCertificate(certificate);
        if (!isVersionEncoded(tbsCertificate)) {
            return (ASN1Sequence) tbsCertificate.getObjectAt(SUBJECTPUBLICKEYINFO_POSITION_V2_V3 - 1);
        }
        return (ASN1Sequence) tbsCertificate.getObjectAt(SUBJECTPUBLICKEYINFO_POSITION_V2_V3);
    }

    public static Optional<ASN1Encodable> getPublicKeyParameters(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence publicKey = ASN1CertificateUtils.getPublicKey(certificate);
        ASN1Sequence algorithmIdentifier = (ASN1Sequence) publicKey.getObjectAt(0);
        if (algorithmIdentifier.size() == 2) {
            return Optional.of(algorithmIdentifier.getObjectAt(1));
        }
        return Optional.empty();
    }

    public static ASN1Sequence getPublicKeyAlgorithmIdentifier(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence publicKey = ASN1CertificateUtils.getPublicKey(certificate);
        return (ASN1Sequence) publicKey.getObjectAt(0);
    }

    public static byte[] getPublicKeySubjectPublicKey(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence publicKey = ASN1CertificateUtils.getPublicKey(certificate);
        ASN1BitString subjectPublicKey = (ASN1BitString) publicKey.getObjectAt(1);
        return subjectPublicKey.getOctets();
    }

    public static String getPublicKeySubjectPublicKeyBase64Encoded(X509Certificate certificate) throws CertificateEncodingException {
        return new String(Base64.encode(getPublicKeySubjectPublicKey(certificate)));
    }

    public static ASN1Encodable getSubject(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence tbsCertificate = getTBSCertificate(certificate);
        if (!isVersionEncoded(tbsCertificate)) {
            return tbsCertificate.getObjectAt(SUBJECT_POSITION_V2_V3 - 1);
        }
        return tbsCertificate.getObjectAt(SUBJECT_POSITION_V2_V3);
    }

    public static ASN1Encodable getIssuer(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence tbsCertificate = getTBSCertificate(certificate);
        if (!isVersionEncoded(tbsCertificate)) {
            return tbsCertificate.getObjectAt(ISSUER_POSITION_V2_V3 - 1);
        }
        return tbsCertificate.getObjectAt(ISSUER_POSITION_V2_V3);
    }

    public static ASN1Encodable getInnerSignature(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence tbsCertificate = getTBSCertificate(certificate);
        if (!isVersionEncoded(tbsCertificate)) {
            return tbsCertificate.getObjectAt(SIGNATURE_POSITION_V2_V3 - 1);
        }
        return tbsCertificate.getObjectAt(SIGNATURE_POSITION_V2_V3);
    }

    public static String getInnerSignatureOID(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence innerSignature = (ASN1Sequence) ASN1CertificateUtils.getInnerSignature(certificate);
        return ((ASN1ObjectIdentifier) innerSignature.getObjectAt(0)).getId();
    }

    public static ASN1Encodable getOuterSignature(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence certificateSequence = getCertificateAsSequence(certificate);
        return certificateSequence.getObjectAt(1);
    }

    private static boolean isVersionEncoded(ASN1Sequence tbsCertificate) {
        return (tbsCertificate.getObjectAt(0) instanceof ASN1TaggedObject) && ((ASN1TaggedObject) tbsCertificate.getObjectAt(0)).getTagNo() == 0;
    }

}
