package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


@Lint(
        name = "e_subject_dn_not_printable_characters",
        description = "X520 Subject fields MUST only contain printable control characters",
        citation = "RFC 5280: Appendix A",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.ZERO)
public class SubjectDnNotPrintableCharacters implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> subjectNameComponents = Utils.getSubjectDNNameComponents(certificate);

        for (AttributeTypeAndValue attributeTypeAndValue : subjectNameComponents) {
            char[] chars = attributeTypeAndValue.getValue().toString().toCharArray();

            for (char character : chars) {

                if ((int) character < ((byte) 0x20 & 0xFF)) {
                    return LintResult.of(Status.ERROR);
                }

                if ((int) character >= ((byte) 0x7F & 0xFF) && (int) character <= ((byte) 0x9F & 0xFF)) {
                    return LintResult.of(Status.ERROR);
                }
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.isSubjectDNEmpty(certificate);
    }
}
