package de.mtg.jzlint.lints.rfc;

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

/********************************************************************
 The user notice has two optional fields: the noticeRef field and the
 explicitText field. Conforming CAs SHOULD NOT use the noticeRef
 option.
 ********************************************************************/
@Lint(
        name = "w_ext_cert_policy_contains_noticeref",
        description = "Compliant certificates SHOULD NOT use the noticeRef option",
        citation = "RFC 5280: 4.2.1.4",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class ExtCertPolicyContainsNoticeref implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {


        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(ASN1OctetString.getInstance(rawCertificatePolicies).getOctets());
        for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
            ASN1Sequence policyQualifiersSequence = policyInformation.getPolicyQualifiers();
            if (policyQualifiersSequence == null) {
                return LintResult.of(Status.PASS);
            }

            ASN1Encodable[] policyQualifiers = policyQualifiersSequence.toArray();
            for (ASN1Encodable policyQualifier : policyQualifiers) {
                ASN1ObjectIdentifier policyQualifierId = (ASN1ObjectIdentifier) ((ASN1Sequence) policyQualifier).getObjectAt(0);
                if (PolicyQualifierId.id_qt_unotice.getId().equals(policyQualifierId.getId())) {
                    ASN1Encodable qualifier = ((ASN1Sequence) policyQualifier).getObjectAt(1);
                    if (qualifier instanceof ASN1Sequence) {
                        ASN1Encodable firstElement = ((ASN1Sequence) qualifier).getObjectAt(0);
                        if (firstElement instanceof ASN1Sequence) {
                            return LintResult.of(Status.WARN);
                        }
                    }
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
