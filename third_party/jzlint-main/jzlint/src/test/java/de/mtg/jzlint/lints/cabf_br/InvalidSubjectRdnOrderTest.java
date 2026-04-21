package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class InvalidSubjectRdnOrderTest {

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ok_01.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ok_02.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ok_03.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ok_04.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ok_05.pem",
            expectedResultStatus = Status.PASS)
    void testCase05() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ok_06.pem",
            expectedResultStatus = Status.PASS)
    void testCase06() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ok_07.pem",
            expectedResultStatus = Status.PASS)
    void testCase07() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ko_01.pem",
            expectedResultStatus = Status.ERROR)
    void testCase08() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ko_02.pem",
            expectedResultStatus = Status.ERROR)
    void testCase09() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ko_03.pem",
            expectedResultStatus = Status.ERROR)
    void testCase10() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ko_04.pem",
            expectedResultStatus = Status.ERROR)
    void testCase11() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ko_05.pem",
            expectedResultStatus = Status.ERROR)
    void testCase12() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ko_06.pem",
            expectedResultStatus = Status.ERROR)
    void testCase13() {
    }

    @LintTest(
            name = "e_invalid_subject_rdn_order",
            filename = "subject_rdn_order_ko_07.pem",
            expectedResultStatus = Status.ERROR)
    void testCase14() {
    }

}