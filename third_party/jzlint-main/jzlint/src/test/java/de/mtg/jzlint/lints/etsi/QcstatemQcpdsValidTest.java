package de.mtg.jzlint.lints.etsi;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class QcstatemQcpdsValidTest {

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiNumberInLangCodeCert21.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiMissingEnglishPdsCert04.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiTwoEnglPdsCert12.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiWrongEncodingLangCodeCert07.pem",
            expectedResultStatus = Status.ERROR)
    void testCase04() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiWrongLangCodeCert05.pem",
            expectedResultStatus = Status.ERROR)
    void testCase05() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiLangCodeUpperCaseCert23.pem",
            expectedResultStatus = Status.PASS)
    void testCase06() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiWrongEncodingUrlCert08.pem",
            expectedResultStatus = Status.ERROR)
    void testCase07() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiTwoLangCodesCert17.pem",
            expectedResultStatus = Status.ERROR)
    void testCase08() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiValidCert03.pem",
            expectedResultStatus = Status.PASS)
    void testCase09() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiValidCert11.pem",
            expectedResultStatus = Status.PASS)
    void testCase10() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiValidAddLangCert13.pem",
            expectedResultStatus = Status.PASS)
    void testCase11() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiEsealValidCert02.pem",
            expectedResultStatus = Status.PASS)
    void testCase12() {
    }

    @LintTest(
            name = "e_qcstatem_qcpds_valid",
            filename = "QcStmtEtsiNoQcStatmentsCert22.pem",
            expectedResultStatus = Status.NA)
    void testCase13() {
    }
}