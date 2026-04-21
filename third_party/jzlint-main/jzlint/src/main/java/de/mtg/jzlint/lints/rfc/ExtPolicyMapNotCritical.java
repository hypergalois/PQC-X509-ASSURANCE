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


/**********************************************************
 RFC 5280: 4.2.1.5.  Policy Mappings
 This extension MAY be supported by CAs and/or applications.
 Conforming CAs SHOULD mark this extension as critical.
 **********************************************************/

@Lint(
        name = "w_ext_policy_map_not_critical",
        description = "Policy mappings should be marked as critical",
        citation = "RFC 5280: 4.2.1.5",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtPolicyMapNotCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isExtensionCritical(certificate, Extension.policyMappings.getId())) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.WARN);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.policyMappings.getId());
    }
}
