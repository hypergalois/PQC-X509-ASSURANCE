package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

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


/*************************************************************************
 RFC 5280: 4.2.1.11
 Conforming CAs MUST NOT issue certificates where policy constraints
 is an empty sequence.  That is, either the inhibitPolicyMapping field
 or the requireExplicitPolicy field MUST be present.  The behavior of
 clients that encounter an empty policy constraints field is not
 addressed in this profile.
 *************************************************************************/

@Lint(
        name = "e_ext_policy_constraints_empty",
        description = "Conforming CAs MUST NOT issue certificates where policy constraints is an empty sequence. That is, either the inhibitPolicyMapping field or the requireExplicityPolicy field MUST be present",
        citation = "RFC 5280: 4.2.1.11",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtPolicyConstraintsEmpty implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawPolicyConstraints = certificate.getExtensionValue(Extension.policyConstraints.getId());
        ASN1Sequence policyConstraintsValue = ASN1Sequence.getInstance(ASN1OctetString.getInstance(rawPolicyConstraints).getOctets());

        if (policyConstraintsValue.size() == 0) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.policyConstraints.getId());
    }
}
