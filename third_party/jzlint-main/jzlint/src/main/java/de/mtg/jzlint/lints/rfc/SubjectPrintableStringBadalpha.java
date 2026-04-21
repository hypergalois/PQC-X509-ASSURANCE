package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_subject_printable_string_badalpha",
        description = "PrintableString type's alphabet only includes a-z, A-Z, 0-9, and 11 special characters",
        citation = "RFC 5280: Appendix B. ASN.1 Notes",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class SubjectPrintableStringBadalpha implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> subjectDNNameComponents = Utils.getSubjectDNNameComponents(certificate);

        List<String> errors = new ArrayList<>();

        for (AttributeTypeAndValue attributeTypeAndValue : subjectDNNameComponents) {
            try {

                if (attributeTypeAndValue.getValue().toASN1Primitive().getEncoded(ASN1Encoding.DER)[0] != 19) {
                    continue;
                }

                ASN1PrintableString value = (ASN1PrintableString) attributeTypeAndValue.getValue();

                String stringValue = value.getString();

                Pattern pattern = Pattern.compile("^[a-zA-Z0-9\\=\\(\\)\\+,\\-.\\/:\\? ']+$");
                Matcher matcher = pattern.matcher(stringValue);
                if (!matcher.matches()) {
                    errors.add(String.format("RawSubject attr oid %s is printable but contains illegal characters.", attributeTypeAndValue.getType().getId()));
                }
            } catch (IOException ex) {
                return LintResult.of(Status.FATAL);
            }
        }

        if (errors.isEmpty()) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR, errors.toString());
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.isSubjectDNEmpty(certificate);
    }

}
