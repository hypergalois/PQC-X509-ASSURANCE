package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_subject_country_name",
        description = "If present, the subject:countryName SHALL contain the two‐letter ISO 3166‐1 country code associated with the location of the Subject",
        citation = "S/MIME BRs: 7.1.4.2.2n",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SubjectCountryName implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> country = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.countryName.getId());

        for (AttributeTypeAndValue attributeTypeAndValue : country) {
            String countryValue = attributeTypeAndValue.getValue().toString();
            String[] isoCountries = Locale.getISOCountries();
            boolean isISO = Arrays.stream(isoCountries).anyMatch(c -> c.equals(countryValue));
            if (!isISO && !"XX".equalsIgnoreCase(countryValue)) {
                return LintResult.of(Status.ERROR);
            }
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return SMIMEUtils.isMailboxValidatedCertificate(certificate);
    }

}
