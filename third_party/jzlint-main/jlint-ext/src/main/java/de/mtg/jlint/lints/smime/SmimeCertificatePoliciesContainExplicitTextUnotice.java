package de.mtg.jlint.lints.smime;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.ASN1VisibleString;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

/**
 * 7.1.2.3 Subscriber certificates
 * a. certificatePolicies (SHALL be present)
 * This extension SHOULD NOT be marked critical. It SHALL include exactly one of the
 * reserved policyIdentifiers listed in Section 7.1.6.1, and MAY contain one or more
 * identifiers documented by the CA in its CP and/or CPS.
 * If the value of this extension includes a PolicyInformation which contains a qualifier of
 * type id_qt_cps (OID: 1.3.6.1.5.5.7.2.1), then the value of the qualifier SHALL be a HTTP or
 * HTTPS URL for the Issuing CA’s CP and/or CPS, Relying Party Agreement, or other pointer to
 * online policy information provided by the Issuing CA. If a qualifier of type id_qt_unotice
 * (OID: 1.3.6.1.5.5.7.2.2) is included, then it SHALL contain explicitText and SHALL NOT
 * contain noticeRef.
 */
@Lint(
        name = "e_smime_certificate_policies_contain_explicittext_unotice",
        description = "Check if qualifier of type id_qt_unotice in the certificate policies of a subscriber certificate contains explicitText rather than noticeRef",
        citation = "SMIME BR 7.1.2.3a",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeCertificatePoliciesContainExplicitTextUnotice implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        byte[] rawValue = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(rawValue);
        for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
            ASN1Sequence policyQualifiersSequence = policyInformation.getPolicyQualifiers();
            if (policyQualifiersSequence == null) {
                continue;
            }
            ASN1Encodable[] policyQualifiers = policyQualifiersSequence.toArray();
            for (ASN1Encodable policyQualifierInfo : policyQualifiers) {
                ASN1Sequence policyQualifierInfoSequence = (ASN1Sequence) policyQualifierInfo;
                ASN1ObjectIdentifier policyQualifierId = (ASN1ObjectIdentifier) policyQualifierInfoSequence.getObjectAt(0);
                if (PolicyQualifierId.id_qt_unotice.getId().equals(policyQualifierId.getId())) {
                    ASN1Sequence userNotice = (ASN1Sequence) policyQualifierInfoSequence.getObjectAt(1);

                    if (userNotice == null || userNotice.size() == 0) {
                        return LintResult.of(Status.ERROR, "userNotice is empty");
                    }

                    if (userNotice.size() == 2) {
                        return LintResult.of(Status.ERROR, "userNotice contains both noticeRef and explicitText");
                    }

                    if (userNotice.size() == 1) {
                        ASN1Encodable userNoticeValue = userNotice.getObjectAt(0);

                        if (userNoticeValue instanceof ASN1Sequence) {
                            return LintResult.of(Status.ERROR, "userNotice contains noticeRef");
                        }

                        boolean isIa5String = userNoticeValue instanceof ASN1IA5String;
                        boolean isVisibleString = userNoticeValue instanceof ASN1VisibleString;
                        boolean isBMPString = userNoticeValue instanceof ASN1BMPString;
                        boolean isUTF8String = userNoticeValue instanceof ASN1UTF8String;

                        if (!(isIa5String || isVisibleString || isBMPString || isUTF8String)) {
                            return LintResult.of(Status.ERROR, "userNotice does not contain explicitText");
                        }
                    }

                }
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        if (!SMIMEUtils.isSMIMEBRSubscriberCertificate(certificate)) {
            return false;
        }

        if (!Utils.hasCertificatePoliciesExtension(certificate)) {
            return false;
        }

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());
        byte[] rawValue = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();

        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(rawValue);
        for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
            ASN1Sequence policyQualifiersSequence = policyInformation.getPolicyQualifiers();

            if (policyQualifiersSequence == null) {
                continue;
            }

            ASN1Encodable[] policyQualifiers = policyQualifiersSequence.toArray();
            for (ASN1Encodable policyQualifier : policyQualifiers) {
                ASN1ObjectIdentifier policyQualifierId = (ASN1ObjectIdentifier) ((ASN1Sequence) policyQualifier).getObjectAt(0);
                if (PolicyQualifierId.id_qt_unotice.getId().equals(policyQualifierId.getId())) {
                    return true;
                }
            }
        }

        return false;
    }

}
