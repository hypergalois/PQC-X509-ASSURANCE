package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

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

/*******************************************************************
 RFC 5280: 4.2.1.4
 To promote interoperability, this profile RECOMMENDS that policy
 information terms consist of only an OID.  Where an OID alone is
 insufficient, this profile strongly recommends that the use of
 qualifiers be limited to those identified in this section.  When
 qualifiers are used with the special policy anyPolicy, they MUST be
 limited to the qualifiers identified in this section.  Only those
 qualifiers returned as a result of path validation are considered.
 ********************************************************************/
@Lint(
        name = "e_ext_cert_policy_disallowed_any_policy_qualifier",
        description = "When qualifiers are used with the special policy anyPolicy, they must be limited to qualifiers identified in this section: (4.2.1.4)",
        citation = "RFC 5280: 4.2.1.4",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC3280)
public class ExtCertPolicyDisallowedAnyPolicyQualifier implements JavaLint {

    private static final String ANY_POLICY_OID = "2.5.29.32.0";

    private List<String> allowedQualifierOIDs = Arrays.asList(PolicyQualifierId.id_qt_unotice.getId(), PolicyQualifierId.id_qt_cps.getId());

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(ASN1OctetString.getInstance(rawCertificatePolicies).getOctets());
        for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {

            if (!ANY_POLICY_OID.equals(policyInformation.getPolicyIdentifier().getId())) {
                continue;
            }

            ASN1Sequence policyQualifiersSequence = policyInformation.getPolicyQualifiers();

            if (policyQualifiersSequence == null) {
                return LintResult.of(Status.PASS);
            }

            ASN1Encodable[] policyQualifiers = policyQualifiersSequence.toArray();
            for (ASN1Encodable policyQualifier : policyQualifiers) {
                ASN1ObjectIdentifier policyQualifierId = (ASN1ObjectIdentifier) ((ASN1Sequence) policyQualifier).getObjectAt(0);
                String qualifierOID = policyQualifierId.getId();
                if (!allowedQualifierOIDs.contains(qualifierOID)) {
                    return LintResult.of(Status.ERROR);
                }
            }
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        if (!Utils.hasCertificatePoliciesExtension(certificate)) {
            return false;
        }

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(ASN1OctetString.getInstance(rawCertificatePolicies).getOctets());
        for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
            if (ANY_POLICY_OID.equals(policyInformation.getPolicyIdentifier().getId())) {
                return true;
            }
        }
        return false;
    }

}
