package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_subject_dn_country_not_printable_string",
        description = "X520 Distinguished Name Country MUST be encoded as PrintableString",
        citation = "RFC 5280: Appendix A",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.ZERO)
public class SubjectDnCountryNotPrintableString implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> subjectNameComponent = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.countryName.getId());

        for (AttributeTypeAndValue attributeTypeAndValue : subjectNameComponent) {
            try {
                if (attributeTypeAndValue.getValue().toASN1Primitive().getEncoded(ASN1Encoding.DER)[0] != 19) {
                    return LintResult.of(Status.ERROR);
                }
            } catch (IOException ex) {
                return LintResult.of(Status.FATAL);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.countryName.getId()).isEmpty();
    }
}
