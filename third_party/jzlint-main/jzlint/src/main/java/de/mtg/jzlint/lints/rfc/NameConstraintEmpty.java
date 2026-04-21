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

/***********************************************************************
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
        name = "e_name_constraint_empty",
        description = "Conforming CAs MUST NOT issue certificates where name constraints is an empty sequence. That is, either the permittedSubtree or excludedSubtree fields must be present",
        citation = "RFC 5280: 4.2.1.10",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class NameConstraintEmpty implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawNameConstraints = certificate.getExtensionValue(Extension.nameConstraints.getId());

        ASN1Sequence nameConstraintsValue = ASN1Sequence.getInstance(ASN1OctetString.getInstance(rawNameConstraints).getOctets());

        if (nameConstraintsValue.size() < 1) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.nameConstraints.getId());
    }
}
