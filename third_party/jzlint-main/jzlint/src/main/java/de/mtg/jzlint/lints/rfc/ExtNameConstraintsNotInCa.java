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

/***********************************************************************
 RFC 5280: 4.2.1.10
 The name constraints extension, which MUST be used only in a CA
 certificate, indicates a name space within which all subject names in
 subsequent certificates in a certification path MUST be located.
 Restrictions apply to the subject distinguished name and apply to
 subject alternative names.  Restrictions apply only when the
 specified name form is present.  If no name of the type is in the
 certificate, the certificate is acceptable.
 ***********************************************************************/

@Lint(
        name = "e_ext_name_constraints_not_in_ca",
        description = "The name constraints extension MUST only be used in CA certificates",
        citation = "RFC 5280: 4.2.1.10",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtNameConstraintsNotInCa implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (!Utils.isCA(certificate)) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.nameConstraints.getId());
    }
}
