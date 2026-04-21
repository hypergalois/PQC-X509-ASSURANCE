package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/*********************************************************************
 RFC 5280: 4.2.1.5
 Each issuerDomainPolicy named in the policy mapping extension SHOULD
 also be asserted in a certificate policies extension in the same
 certificate.  Policies SHOULD NOT be mapped either to or from the
 special value anyPolicy (section 4.2.1.5).
 *********************************************************************/

@Lint(
        name = "w_ext_policy_map_not_in_cert_policy",
        description = "Each issuerDomainPolicy named in the policy mappings extension should also be asserted in a certificate policies extension",
        citation = "RFC 5280: 4.2.1.5",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC3280)
public class ExtPolicyMapNotInCertPolicy implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<String> issuerDomainPolicies = getIssuerDomainPolicies(certificate);

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return LintResult.of(Status.WARN);
        }

        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(ASN1OctetString.getInstance(rawCertificatePolicies).getOctets());
        for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
            String oid = policyInformation.getPolicyIdentifier().getId();
            if (!issuerDomainPolicies.contains(oid)) {
                return LintResult.of(Status.WARN);
            }
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.policyMappings.getId());
    }


    private static List<String> getIssuerDomainPolicies(X509Certificate certificate) {
        byte[] rawPolicyMappings = certificate.getExtensionValue(Extension.policyMappings.getId());
        ASN1Sequence policyMappings = ASN1Sequence.getInstance(ASN1OctetString.getInstance(rawPolicyMappings).getOctets());
        Iterator<ASN1Encodable> iterator = policyMappings.iterator();
        List<String> issuerDomainPolicies = new ArrayList<>();
        while (iterator.hasNext()) {
            ASN1Sequence policyMapping = ASN1Sequence.getInstance(iterator.next());
            ASN1ObjectIdentifier issuerDomainPolicy = (ASN1ObjectIdentifier) policyMapping.getObjectAt(0);
            issuerDomainPolicies.add(issuerDomainPolicy.getId());
        }
        return issuerDomainPolicies;
    }
}
