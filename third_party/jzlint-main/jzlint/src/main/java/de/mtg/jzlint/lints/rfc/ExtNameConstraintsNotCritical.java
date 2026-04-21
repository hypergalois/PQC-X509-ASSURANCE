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

/************************************************************************
 Restrictions are defined in terms of permitted or excluded name
 subtrees.  Any name matching a restriction in the excludedSubtrees
 field is invalid regardless of information appearing in the
 permittedSubtrees.  Conforming CAs MUST mark this extension as
 critical and SHOULD NOT impose name constraints on the x400Address,
 ediPartyName, or registeredID name forms.  Conforming CAs MUST NOT
 issue certificates where name constraints is an empty sequence.  That
 is, either the permittedSubtrees field or the excludedSubtrees MUST
 be present.
 ************************************************************************/

@Lint(
        name = "e_ext_name_constraints_not_critical",
        description = "If it is included, conforming CAs MUST mark the name constraints extension as critical",
        citation = "RFC 5280: 4.2.1.10",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtNameConstraintsNotCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isExtensionCritical(certificate, Extension.nameConstraints.getId())) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.nameConstraints.getId());
    }
}
