package de.mtg.jzlint.lints.community;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


@Lint(
        name = "n_multiple_subject_rdn",
        description = "Certificates typically do not have have multiple attributes in a single RDN (subject). This may be an error.",
        citation = "lint.AWSLabs certlint",
        source = Source.COMMUNITY,
        effectiveDate = EffectiveDate.ZERO)
public class MultipleSubjectRdn implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            if (Utils.hasMultiValuedRDNInSubject(certificate)) {
                return LintResult.of(Status.NOTICE);
            }
        } catch (CertificateEncodingException ex) {
            return LintResult.of(Status.FATAL);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

}
