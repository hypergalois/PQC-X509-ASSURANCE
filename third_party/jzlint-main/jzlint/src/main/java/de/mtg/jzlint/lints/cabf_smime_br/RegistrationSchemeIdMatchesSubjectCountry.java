package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

// Regex to match the start of an organization identifier: 3 character registration scheme identifier and 2 character ISO 3166 country code
//        var countryRegex = regexp.MustCompile(`^([A-Z]{3})([A-Z]{2})`)

@Lint(
        name = "e_registration_scheme_id_matches_subject_country",
        description = "The country code used in the Registration Scheme identifier SHALL match that of the subject:countryName in the Certificate as specified in Section 7.1.4.2.2",
        citation = "Appendix A.1",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class RegistrationSchemeIdMatchesSubjectCountry implements JavaLint {

    private static final String COUNTRY_REGEX = "^([A-Z]{3})([A-Z]{2})";
    public static final String INT = "INT";
    public static final String LEI = "LEI";

    @Override
    public LintResult execute(X509Certificate certificate) {
        List<String> countryValues;
        List<String> organizationIdentifierValues;
        try {
            countryValues = Utils.getAllAttributeValuesInSubject(certificate, X509ObjectIdentifiers.countryName.getId());
            organizationIdentifierValues = Utils.getAllAttributeValuesInSubject(certificate, BCStyle.ORGANIZATION_IDENTIFIER.getId());
        } catch (CertificateEncodingException ex) {
            return LintResult.of(Status.FATAL);
        }

        for (String value : organizationIdentifierValues) {
            String result = verifySMIMEOrganizationIdentifierContainsSubjectNameCountry(value, countryValues.get(0));

            if (result != null) {
                return LintResult.of(Status.ERROR, result);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        try {
            List<String> countryValues = Utils.getAllAttributeValuesInSubject(certificate, X509ObjectIdentifiers.countryName.getId());

            if (countryValues == null || countryValues.isEmpty()) {
                return false;
            }

            if (countryValues.size() != 1) {
                return false;
            }

            if (countryValues.get(0).length() != 2) {
                return false;
            }

            boolean orgIDsAreInternational = true;

            List<String> organizationIdentifierValues = Utils.getAllAttributeValuesInSubject(certificate, BCStyle.ORGANIZATION_IDENTIFIER.getId());

            if (organizationIdentifierValues == null || organizationIdentifierValues.isEmpty()) {
                return false;
            }

            for (String value : organizationIdentifierValues) {
                Pattern pattern = Pattern.compile(COUNTRY_REGEX);
                Matcher matcher = pattern.matcher(value);
                boolean matched = matcher.find();

                if (!matched) {
                    return false;
                }

                if (matcher.group(1).length() < 3) {
                    return false;
                }

                orgIDsAreInternational = orgIDsAreInternational && (INT.equals(matcher.group(1)) || LEI.equals(matcher.group(1)));

            }

            if (orgIDsAreInternational) {
                return false;
            }

        } catch (CertificateEncodingException ex) {
            throw new RuntimeException(ex);
        }


        return SMIMEUtils.isOrganizationValidatedCertificate(certificate) || SMIMEUtils.isSponsorValidatedCertificate(certificate);
    }

    private String verifySMIMEOrganizationIdentifierContainsSubjectNameCountry(String organizationIdentifier, String country) {
        Pattern pattern = Pattern.compile(COUNTRY_REGEX);
        Matcher matcher = pattern.matcher(organizationIdentifier);
        matcher.find();
        String identifierCountry = matcher.group(2);

        if (INT.equals(matcher.group(1)) || LEI.equals(matcher.group(1))) {
            return null;
        }

        if (!country.equals(identifierCountry)) {
            return "the country code used in the Registration Scheme identifier SHALL match that of the subject:countryName";
        }
        return null;
    }

}
