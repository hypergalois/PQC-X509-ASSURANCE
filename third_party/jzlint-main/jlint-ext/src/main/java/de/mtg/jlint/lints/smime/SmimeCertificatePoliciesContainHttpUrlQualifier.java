package de.mtg.jlint.lints.smime;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
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
        name = "e_smime_certificate_policies_contain_http_url_qualifier",
        description = "Check if qualifier of type id_qt_cps in the certificate policies of a subscriber certificate points to an HTTP or HTTP URL",
        citation = "SMIME BR 7.1.2.3a",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeCertificatePoliciesContainHttpUrlQualifier implements JavaLint {

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
                if (PolicyQualifierId.id_qt_cps.getId().equals(policyQualifierId.getId())) {
                    ASN1IA5String cPSuri = (ASN1IA5String) policyQualifierInfoSequence.getObjectAt(1);

                    if (cPSuri.getString().startsWith("https://") || cPSuri.getString().startsWith("http://")) {
                        try {
                            new URL(cPSuri.getString()).toURI();
                        } catch (URISyntaxException | MalformedURLException ex) {
                            return LintResult.of(Status.ERROR);
                        }
                    } else {
                        return LintResult.of(Status.ERROR);
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
                if (PolicyQualifierId.id_qt_cps.getId().equals(policyQualifierId.getId())) {
                    return true;
                }
            }
        }

        return false;
    }

}