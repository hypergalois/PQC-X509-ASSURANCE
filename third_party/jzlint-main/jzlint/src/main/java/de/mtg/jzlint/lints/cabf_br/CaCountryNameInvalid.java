package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;

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
 BRs: 7.1.2.1e
 The	Certificate	Subject	MUST contain the following:
 -	countryName	(OID 2.5.4.6).
 This field MUST	contain	the	two-letter	ISO	3166-1 country code	for	the country
 in which the CA’s place	of business	is located.
 ************************************************/

@Lint(
        name = "e_ca_country_name_invalid",
        description = "Root and Subordinate CA certificates MUST have a two-letter country code specified in ISO 3166-1",
        citation = "BRs: 7.1.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class CaCountryNameInvalid implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> countryName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.countryName.getId());
        String[] isoCountries = Locale.getISOCountries();

        for (AttributeTypeAndValue country : countryName) {

            String countryValue = country.getValue().toString();

            Predicate<String> isISOCountrySame = isoCountry -> isoCountry.equals(countryValue);
            if (Arrays.stream(isoCountries).noneMatch(isISOCountrySame)) {
                return LintResult.of(Status.ERROR);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        List<AttributeTypeAndValue> country = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.countryName.getId());

        if (country.isEmpty()) {
            return false;
        }

        return Utils.isCA(certificate);
    }

}
