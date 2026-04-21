package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1OctetString;
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

/************************************************
 The certificate policies extension contains a sequence of one or more
 policy information terms, each of which consists of an object identifier
 (OID) and optional qualifiers. Optional qualifiers, which MAY be present,
 are not expected to change the definition of the policy. A certificate
 policy OID MUST NOT appear more than once in a certificate policies extension.
 ************************************************/
@Lint(
        name = "e_ext_cert_policy_duplicate",
        description = "A certificate policy OID must not appear more than once in the extension",
        citation = "RFC 5280: 4.2.1.4",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class ExtCertPolicyDuplicate implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        List<String> presentOIDs = new ArrayList<>();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(ASN1OctetString.getInstance(rawCertificatePolicies).getOctets());
        for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {

            String oid = policyInformation.getPolicyIdentifier().getId();
            boolean removed = presentOIDs.remove(oid);
            if (removed) {
                return LintResult.of(Status.ERROR);
            }
            presentOIDs.add(oid);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasCertificatePoliciesExtension(certificate);
    }
}
