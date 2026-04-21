package de.mtg.jlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.utils.Utils;

/************************************************
 RFC 5280: A.1
 * In this Appendix, there is a list of upperbounds
 for fields in a x509 Certificate. *
 ub-state-name INTEGER ::= 128
 ************************************************/

@Lint(
        name = "e_issuer_state_name_max_length",
        description = "The 'State Name' field of the issuer MUST be less than 129 characters",
        citation = "RFC 5280: A.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class IssuerStateNameMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return IssuerCommonNameMaxLength.isIssuerComponentGreaterThan(certificate, X509ObjectIdentifiers.stateOrProvinceName.getId(), 128);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getIssuerDNNameComponent(certificate, X509ObjectIdentifiers.stateOrProvinceName.getId()).isEmpty();
    }

}
