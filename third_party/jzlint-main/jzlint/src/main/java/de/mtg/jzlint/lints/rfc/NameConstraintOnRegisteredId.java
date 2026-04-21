package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.utils.Utils;

/*******************************************************************
 RFC 5280: 4.2.1.10
 Restrictions are defined in terms of permitted or excluded name
 subtrees.  Any name matching a restriction in the excludedSubtrees
 field is invalid regardless of information appearing in the
 permittedSubtrees.  Conforming CAs MUST mark this extension as
 critical and SHOULD NOT impose name constraints on the x400Address,
 ediPartyName, or registeredID name forms.  Conforming CAs MUST NOT
 issue certificates where name constraints is an empty sequence.  That
 is, either the permittedSubtrees field or the excludedSubtrees MUST
 be present.
 *******************************************************************/

@Lint(
        name = "w_name_constraint_on_registered_id",
        description = "The name constraints extension SHOULD NOT impose constraints on the registeredID name form",
        citation = "RFC 5280: 4.2.1.10",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class NameConstraintOnRegisteredId implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return NameConstraintOnEdiPartyName.nameConstraintsHaveBaseWithTag(certificate, 8);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.nameConstraints.getId());
    }


}
