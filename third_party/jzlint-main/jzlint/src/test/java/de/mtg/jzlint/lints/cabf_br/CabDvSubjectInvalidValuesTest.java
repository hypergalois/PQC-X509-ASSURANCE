package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CabDvSubjectInvalidValuesTest {

    @LintTest(
            name = "e_cab_dv_subject_invalid_values",
            filename = "domainValGoodSubject.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "ne - DV with valid values in subjectDN, before SC62")
    void testCase01() {
    }

    @LintTest(
            name = "e_cab_dv_subject_invalid_values",
            filename = "dvWithOrganization.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - DV with organization in subjectDN, on SC62")
    void testCase02() {
    }

    @LintTest(
            name = "e_cab_dv_subject_invalid_values",
            filename = "dvWithSerialNumber.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - DV with serialNumber in subjectDN, on SC62")
    void testCase03() {
    }

    @LintTest(
            name = "e_cab_dv_subject_invalid_values",
            filename = "dvWithCNAndCountry.pem",
            expectedResultStatus = Status.WARN,
            certificateDescription = "warn - DV with valid values in subjectDN, with CN, on SC62")
    void testCase04() {
    }

    @LintTest(
            name = "e_cab_dv_subject_invalid_values",
            filename = "dvCountry.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - DV with valid values in subjectDN, country only, on SC62")
    void testCase05() {
    }

    @LintTest(
            name = "e_cab_dv_subject_invalid_values",
            filename = "dvEmptySubject.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - DV with empty subjectDN, on SC62")
    void testCase06() {
    }

    @LintTest(
            name = "e_cab_dv_subject_invalid_values",
            filename = "evAllGood.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - EV certificate")
    void testCase07() {
    }

}
