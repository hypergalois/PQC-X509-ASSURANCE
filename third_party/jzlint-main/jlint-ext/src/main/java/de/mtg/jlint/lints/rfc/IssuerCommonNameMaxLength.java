package de.mtg.jlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 RFC 5280: A.1
 * In this Appendix, there is a list of upperbounds
 for fields in a x509 Certificate. *
 ub-common-name INTEGER ::= 64
 ************************************************/

@Lint(
        name = "e_issuer_common_name_max_length",
        description = "The commonName field of the issuer MUST be less than 65 characters",
        citation = "RFC 5280: A.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class IssuerCommonNameMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return IssuerCommonNameMaxLength.isIssuerComponentGreaterThan(certificate, X509ObjectIdentifiers.commonName.getId(), 64);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getIssuerDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId()).isEmpty();
    }

    protected static LintResult isIssuerComponentGreaterThan(X509Certificate certificate, String oid, int length) {
        List<AttributeTypeAndValue> issuerNameComponent = Utils.getIssuerDNNameComponent(certificate, oid);

        for (AttributeTypeAndValue attributeTypeAndValue : issuerNameComponent) {
            if (attributeTypeAndValue.getValue().toString().length() > length) {
                return LintResult.of(Status.ERROR);
            }
        }

        return LintResult.of(Status.PASS);
    }

}
