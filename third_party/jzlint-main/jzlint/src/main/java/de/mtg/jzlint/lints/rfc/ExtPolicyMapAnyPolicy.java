package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/********************************************************************
 RFC 5280: 4.2.1.5
 Each issuerDomainPolicy named in the policy mappings extension SHOULD
 also be asserted in a certificate policies extension in the same
 certificate.  Policies MUST NOT be mapped either to or from the
 special value anyPolicy (Section 4.2.1.4).
 ********************************************************************/

@Lint(
        name = "e_ext_policy_map_any_policy",
        description = "Policies must not be mapped to or from the anyPolicy value",
        citation = "RFC 5280: 4.2.1.5",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC3280)
public class ExtPolicyMapAnyPolicy implements JavaLint {

    private static final String ANY_POLICY_OID = "2.5.29.32.0";

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawPolicyMappings = certificate.getExtensionValue(Extension.policyMappings.getId());

        ASN1Sequence policyMappings = ASN1Sequence.getInstance(ASN1OctetString.getInstance(rawPolicyMappings).getOctets());

        Iterator<ASN1Encodable> iterator = policyMappings.iterator();

        while (iterator.hasNext()) {
            ASN1Sequence policyMapping = ASN1Sequence.getInstance(iterator.next());
            ASN1ObjectIdentifier issuerDomainPolicy = (ASN1ObjectIdentifier) policyMapping.getObjectAt(0);
            ASN1ObjectIdentifier subjectDomainPolicy = (ASN1ObjectIdentifier) policyMapping.getObjectAt(1);

            if (ANY_POLICY_OID.equalsIgnoreCase(issuerDomainPolicy.getId()) || ANY_POLICY_OID.equalsIgnoreCase(subjectDomainPolicy.getId())) {
                return LintResult.of(Status.ERROR);
            }
        }
        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.policyMappings.getId());
    }
}
