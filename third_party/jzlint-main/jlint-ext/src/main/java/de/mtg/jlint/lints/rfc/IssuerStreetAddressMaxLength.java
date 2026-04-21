package de.mtg.jlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.style.BCStyle;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.utils.Utils;

/************************************************
 ITU-T X.520 (02/2001) UpperBounds
 ub-street-address INTEGER ::= 128
 ************************************************/

@Lint(
        name = "e_issuer_street_address_max_length",
        description = "The 'StreetAddress' field of the issuer MUST be less than 129 characters",
        citation = "ITU-T X.520 (02/2001) UpperBounds",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class IssuerStreetAddressMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return IssuerCommonNameMaxLength.isIssuerComponentGreaterThan(certificate, BCStyle.STREET.getId(), 128);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getIssuerDNNameComponent(certificate, BCStyle.STREET.getId()).isEmpty();
    }

}
