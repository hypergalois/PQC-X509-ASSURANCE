package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
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
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_policy_qualifiers_other_than_cps_not_permitted",
        description = "Policy Qualifiers other than id-qt-cps MUST NOT be present for certificates issued on or after September 15, 2023",
        citation = "BRs: 7.1.2.7.9",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SC62_EFFECTIVE_DATE)
public class PolicyQualifiersOtherThanCpsNotPermitted implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());
        final byte[] rawValue = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();

        final CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(rawValue);
        for (final PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
            final ASN1Sequence policyQualifiersSequence = policyInformation.getPolicyQualifiers();

            if (policyQualifiersSequence == null) {
                continue;
            }

            final ASN1Encodable[] policyQualifiers = policyQualifiersSequence.toArray();
            for (final ASN1Encodable policyQualifier : policyQualifiers) {
                final ASN1ObjectIdentifier policyQualifierId = (ASN1ObjectIdentifier) ((ASN1Sequence) policyQualifier).getObjectAt(0);
                if (!PolicyQualifierId.id_qt_cps.getId().equals(policyQualifierId.getId())) {
                    return LintResult.of(Status.ERROR);
                }
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasCertificatePoliciesExtension(certificate);
    }

}
