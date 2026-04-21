package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectCommonNameNotFromSanTest {

    @LintTest(
            name = "e_subject_common_name_not_from_san",
            filename = "SANRegisteredIdBeginning.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Pass - commonName in SAN.DNSNames")
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_common_name_not_from_san",
            filename = "SANCaseNotMatchingCN.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Pass - common name in SAN.DNSNames but case mismatch")
    void testCase02() {
    }

    @LintTest(
            name = "e_subject_common_name_not_from_san",
            filename = "SANWithMissingCN.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - common name not in SAN.DNSNames")
    void testCase03() {
    }

    @LintTest(
            name = "e_subject_common_name_not_from_san",
            filename = "SANWithCNSeptember2021.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "NE - certificate issued before 21 August 2021")
    void testCase04() {
    }

}