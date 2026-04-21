package de.mtg.jzlint.utils;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;

public final class SMIMEUtils {

    public static final String MAILBOX_VALIDATED_LEGACY = "2.23.140.1.5.1.1";
    public static final String MAILBOX_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.1.2";
    public static final String MAILBOX_VALIDATED_STRICT = "2.23.140.1.5.1.3";
    public static final String ORGANIZATION_VALIDATED_LEGACY = "2.23.140.1.5.2.1";
    public static final String ORGANIZATION_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.2.2";
    public static final String ORGANIZATION_VALIDATED_STRICT = "2.23.140.1.5.2.3";
    public static final String SPONSOR_VALIDATED_LEGACY = "2.23.140.1.5.3.1";
    public static final String SPONSOR_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.3.2";
    public static final String SPONSOR_VALIDATED_STRICT = "2.23.140.1.5.3.3";
    public static final String INDIVIDUAL_VALIDATED_LEGACY = "2.23.140.1.5.4.1";
    public static final String INDIVIDUAL_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.4.2";
    public static final String INDIVIDUAL_VALIDATED_STRICT = "2.23.140.1.5.4.3";

    private static final List<String> MAILBOX_VALIDATED_OIDS = Arrays.asList(
            MAILBOX_VALIDATED_LEGACY,
            MAILBOX_VALIDATED_MULTIPURPOSE,
            MAILBOX_VALIDATED_STRICT
    );

    private static final List<String> LEGACY_OIDS = Arrays.asList(
            MAILBOX_VALIDATED_LEGACY,
            ORGANIZATION_VALIDATED_LEGACY,
            SPONSOR_VALIDATED_LEGACY,
            INDIVIDUAL_VALIDATED_LEGACY
    );

    private static final List<String> MULTIPURPOSE_OIDS = Arrays.asList(
            MAILBOX_VALIDATED_MULTIPURPOSE,
            ORGANIZATION_VALIDATED_MULTIPURPOSE,
            SPONSOR_VALIDATED_MULTIPURPOSE,
            INDIVIDUAL_VALIDATED_MULTIPURPOSE
    );

    private static final List<String> STRICT_OIDS = Arrays.asList(
            MAILBOX_VALIDATED_STRICT,
            ORGANIZATION_VALIDATED_STRICT,
            SPONSOR_VALIDATED_STRICT,
            INDIVIDUAL_VALIDATED_STRICT
    );

    private static final List<String> ORGANIZATION_VALIDATED_OIDS = Arrays.asList(
            ORGANIZATION_VALIDATED_LEGACY,
            ORGANIZATION_VALIDATED_MULTIPURPOSE,
            ORGANIZATION_VALIDATED_STRICT,
            INDIVIDUAL_VALIDATED_STRICT
    );

    private static final List<String> SPONSOR_VALIDATED_OIDS = Arrays.asList(
            SPONSOR_VALIDATED_LEGACY,
            SPONSOR_VALIDATED_MULTIPURPOSE,
            SPONSOR_VALIDATED_STRICT
    );

    private static final List<String> INDIVIDUAL_VALIDATED_OIDS = Arrays.asList(
            INDIVIDUAL_VALIDATED_LEGACY,
            INDIVIDUAL_VALIDATED_MULTIPURPOSE,
            INDIVIDUAL_VALIDATED_STRICT
    );

    private static final Function<PolicyInformation, String> getOID = p -> p.getPolicyIdentifier().getId();

    // taken from https://www.baeldung.com/java-email-validation-regex
    private static final String REGEX_PATTERN = "^(?=.{1,64}@)[\\p{L}0-9_-]+(\\.[\\p{L}0-9_-]+)*@[^-][\\p{L}0-9-]+(\\.[\\p{L}0-9-]+)*(\\.[\\p{L}]{2,})$";
    private static final String REGEX_PATTERN_PLUS = "^(?=.{1,64}@)[A-Za-z0-9\\+_-]+(\\.[A-Za-z0-9\\+_-]+)*@[^-][A-Za-z0-9\\+-]+(\\.[A-Za-z0-9\\+-]+)*(\\.[A-Za-z]{2,})$";
    private static final Pattern PATTERN = Pattern.compile(REGEX_PATTERN);
    private static final Pattern PATTERN_PLUS = Pattern.compile(REGEX_PATTERN_PLUS);

    private SMIMEUtils() {
        // empty
    }

    public static boolean isMailboxValidatedCertificate(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);

        Predicate<PolicyInformation> isMailboxValidatedPolicy = p -> MAILBOX_VALIDATED_OIDS.contains(getOID.apply(p));

        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isMailboxValidatedPolicy);
    }

    public static boolean isLegacySMIMECertificate(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);

        Predicate<PolicyInformation> isLegacy = p -> LEGACY_OIDS.contains(getOID.apply(p));

        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isLegacy);
    }

    public static boolean isMultipurposeSMIMECertificate(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);
        Predicate<PolicyInformation> isMailboxValidatedPolicy = p -> MULTIPURPOSE_OIDS.contains(getOID.apply(p));
        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isMailboxValidatedPolicy);

    }

    public static boolean isStrictSMIMECertificate(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);
        Predicate<PolicyInformation> isStrictPolicy = p -> STRICT_OIDS.contains(getOID.apply(p));
        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isStrictPolicy);

    }

    public static boolean isSMIMEBRCertificate(X509Certificate certificate) {
        return isLegacySMIMECertificate(certificate) ||
                isMultipurposeSMIMECertificate(certificate) ||
                isStrictSMIMECertificate(certificate);
    }

    public static boolean isSMIMEBRSubscriberCertificate(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && isSMIMEBRCertificate(certificate);
    }

    public static boolean isOrganizationValidatedCertificate(X509Certificate certificate) {
        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);
        Predicate<PolicyInformation> isOrganizationValidatedPolicy = p -> ORGANIZATION_VALIDATED_OIDS.contains(getOID.apply(p));
        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isOrganizationValidatedPolicy);
    }

    public static boolean isSponsorValidatedCertificate(X509Certificate certificate) {
        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);
        Predicate<PolicyInformation> isSponsorValidatedPolicy = p -> SPONSOR_VALIDATED_OIDS.contains(getOID.apply(p));
        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isSponsorValidatedPolicy);
    }

    public static boolean isIndividualValidatedCertificate(X509Certificate certificate) {
        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);
        Predicate<PolicyInformation> isIndividualValidatedPolicy = p -> INDIVIDUAL_VALIDATED_OIDS.contains(getOID.apply(p));
        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isIndividualValidatedPolicy);
    }

    public static boolean isValidEmailAddress(String candidate) {
        if (!PATTERN.matcher(candidate).matches()) {
            if (!PATTERN_PLUS.matcher(candidate).matches()) {
                return false;
            }
        }
        return true;
    }

    public static List<String> getSmtpUTF8Mailboxes(X509Certificate certificate) throws IOException {

        byte[] rawSAN = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

        if (rawSAN == null) {
            return new ArrayList<>();
        }

        GeneralNames generalNames = Utils.getGeneralNames(rawSAN);
        GeneralName[] names = generalNames.getNames();
        List<GeneralName> otherNames = new ArrayList<>();
        Arrays.stream(names).filter(generalName -> generalName.getTagNo() == 0).forEach(otherNames::add);

        List<String> emails = new ArrayList<>();
        for (GeneralName otherName : otherNames) {
            byte[] encoded = otherName.getEncoded(ASN1Encoding.DER);
            ASN1Sequence sequence = ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(encoded).getBaseObject());
            ASN1ObjectIdentifier typeId = (ASN1ObjectIdentifier) sequence.getObjectAt(0);
            if ("1.3.6.1.5.5.7.8.9".equals(typeId.getId())) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence.getObjectAt(1);
                ASN1UTF8String utf8String = (ASN1UTF8String) taggedObject.getBaseObject();
                emails.add(utf8String.getString());
            }
        }
        return emails;
    }

}
