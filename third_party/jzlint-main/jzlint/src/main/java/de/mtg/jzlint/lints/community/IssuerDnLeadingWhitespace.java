package de.mtg.jzlint.lints.community;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "w_issuer_dn_leading_whitespace",
        description = "AttributeValue in issuer RelativeDistinguishedName sequence SHOULD NOT have leading whitespace",
        citation = "awslabs certlint",
        source = Source.COMMUNITY,
        effectiveDate = EffectiveDate.ZERO)
public class IssuerDnLeadingWhitespace implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> allAttributeValuesInIssuer = Utils.getAllAttributeValuesInIssuer(certificate);

            for (String value : allAttributeValuesInIssuer) {
                if (value.startsWith(" ")) {
                    return LintResult.of(Status.WARN);
                }
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
