package de.mtg.jzlint.lints.cabf_br;

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
import de.mtg.jzlint.utils.Utils;

/**************************************************************************************************************
 BRs: 7.1.4.2.2
 Certificate Field: issuer:countryName (OID 2.5.4.6)
 Required/Optional: Required
 Contents: This field MUST contain the two-letter ISO 3166-1 country code for the country in which the issuer’s
 place of business is located.
 **************************************************************************************************************/

@Lint(
        name = "e_subject_country_not_iso",
        description = "The country name field MUST contain the two-letter ISO code for the country or XX",
        citation =  "BRs: 7.1.4.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubjectCountryNotIso implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> countryName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.countryName.getId());
        String[] isoCountries = Locale.getISOCountries();

        for (AttributeTypeAndValue country : countryName) {

            String countryValue = country.getValue().toString();

            if (Arrays.stream(isoCountries).noneMatch(countryValue::equals)) {
                return LintResult.of(Status.ERROR);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

}
