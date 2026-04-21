package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

/************************************************
 These fields MUST only appear if the version is 2 or 3 (Section 4.1.2.1).
 These fields MUST NOT appear if the version is 1. The subject and issuer
 unique identifiers are present in the certificate to handle the possibility
 of reuse of subject and/or issuer names over time. This profile RECOMMENDS
 that names not be reused for different entities and that Internet certificates
 not make use of unique identifiers. CAs conforming to this profile MUST NOT
 generate certificates with unique identifiers. Applications conforming to
 this profile SHOULD be capable of parsing certificates that include unique
 identifiers, but there are no processing requirements associated with the
 unique identifiers.
 ************************************************/
@Lint(
        name = "e_cert_contains_unique_identifier",
        description = "CAs MUST NOT generate certificate with unique identifiers",
        citation = "RFC 5280: 4.1.2.8",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class CertContainsUniqueIdentifier implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (certificate.getIssuerUniqueID() == null && certificate.getSubjectUniqueID() == null) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }
}
