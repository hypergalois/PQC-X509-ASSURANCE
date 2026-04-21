package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RegistrationSchemeIdMatchesSubjectCountryTest {

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/organization_validated_with_matching_country.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - organization validated certificate with subject:Name:Country matching subject:organizationIdentifier")
    void testCase01() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/sponsor_validated_with_matching_country.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - sponsor validated certificate with subject:Name:Country matching subject:organizationIdentifier")
    void testCase02() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/with_lei_and_gov_organizationidentifier.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - certificate with one LEI and one GOV organization identifier")
    void testCase03() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/individual_validated_with_matching_country.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - individual validated certificate")
    void testCase04() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/organization_validatged_with_no_country_specified.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - no country specified in certificate")
    void testCase05() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/with_single_lei_organizationidentifier.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - certificate with LEI organization identifier")
    void testCase06() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/with_single_int_organizationidentifier.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - certificate with INT organization identifier")
    void testCase07() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/organization_validated_with_incorrect_format_identifier.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "NA - organization validated certificate with subject:organizationIdentifier in incorrect format")
    void testCase08() {
    }

    @LintTest(
            name = "e_registration_scheme_id_matches_subject_country",
            filename = "smime/organization_validated_with_non_matching_country.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - organization validated certificate with subject:Name:Country not matching subject:organizationIdentifier")
    void testCase09() {
    }

}