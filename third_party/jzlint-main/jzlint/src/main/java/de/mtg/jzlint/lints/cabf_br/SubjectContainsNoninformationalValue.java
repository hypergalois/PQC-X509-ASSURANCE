package de.mtg.jzlint.lints.cabf_br;

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

/**********************************************************************************************************************
 BRs: 7.1.4.2.2
 Other Subject Attributes
 With the exception of the subject:organizationalUnitName (OU) attribute, optional attributes, when present within
 the subject field, MUST contain information that has been verified by the CA. Metadata such as ‘.’, ‘-‘, and ‘ ‘ (i.e.
 space) characters, and/or any other indication that the value is absent, incomplete, or not applicable, SHALL NOT
 be used.
 **********************************************************************************************************************/

@Lint(
        name = "e_subject_contains_noninformational_value",
        description = "Subject name fields must not contain '.','-',' ' or any other indication that the field has been omitted",
        citation = "BRs: 7.1.4.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubjectContainsNoninformationalValue implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> attributeTypeAndValues = Utils.getSubjectDNNameComponents(certificate);

        for (AttributeTypeAndValue attributeTypeAndValue : attributeTypeAndValues) {

            char[] characters = attributeTypeAndValue.getValue().toString().toCharArray();

            if (!checkAlphaNumericOrUTF8Present(characters)) {
                return LintResult.of(Status.ERROR);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

    public boolean checkAlphaNumericOrUTF8Present(char[] characters) {
        for (char character : characters) {
            if ((character >= 'a' && character <= 'z')
                    || (character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9')
                    || character > 127) {
                return true;
            }
        }
        return false;
    }

}
