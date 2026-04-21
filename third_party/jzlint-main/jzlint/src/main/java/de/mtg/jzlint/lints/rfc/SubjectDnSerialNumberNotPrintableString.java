package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.style.BCStyle;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_subject_dn_serial_number_not_printable_string",
        description = "X520 Distinguished Name SerialNumber MUST be encoded as PrintableString",
        citation = "RFC 5280: Appendix A",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.ZERO)
public class SubjectDnSerialNumberNotPrintableString implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> serialNumber = Utils.getIssuerDNNameComponent(certificate, BCStyle.SERIALNUMBER.getId());

        for (AttributeTypeAndValue attributeTypeAndValue : serialNumber) {
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
        return !Utils.getSubjectDNNameComponent(certificate, BCStyle.SERIALNUMBER.getId()).isEmpty();
    }
}
