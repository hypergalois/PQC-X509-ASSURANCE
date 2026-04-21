package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertGivenNameSurnameContainsCorrectPolicyTest {

    @LintTest(
            name = "e_sub_cert_given_name_surname_contains_correct_policy",
            filename = "surnameCorrectPolicy.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_given_name_surname_contains_correct_policy",
            filename = "givenNameIncorrectPolicy.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }


    @LintTest(
            name = "e_sub_cert_given_name_surname_contains_correct_policy",
            filename = "surnameIncorrectPolicy.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

}