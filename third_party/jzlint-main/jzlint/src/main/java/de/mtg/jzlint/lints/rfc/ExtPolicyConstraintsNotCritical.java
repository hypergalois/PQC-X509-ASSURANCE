package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


/************************************************
 RFC 5280: 4.2.1.11
 Conforming CAs MUST mark this extension as critical.
 ************************************************/

@Lint(
        name = "e_ext_policy_constraints_not_critical",
        description = "Conforming CAs MUST mark the policy constraints extension as critical",
        citation = "RFC 5280: 4.2.1.11",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class ExtPolicyConstraintsNotCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isExtensionCritical(certificate, Extension.policyConstraints.getId())) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.policyConstraints.getId());
    }
}
