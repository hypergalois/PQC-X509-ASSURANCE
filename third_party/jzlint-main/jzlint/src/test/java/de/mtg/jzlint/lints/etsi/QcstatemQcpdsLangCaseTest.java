package de.mtg.jzlint.lints.etsi;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class QcstatemQcpdsLangCaseTest {

    @LintTest(
            name = "w_qcstatem_qcpds_lang_case",
            filename = "QcStmtEtsiTwoEnglPdsCert12.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "w_qcstatem_qcpds_lang_case",
            filename = "QcStmtEtsiLangCodeUpperCaseCert23.pem",
            expectedResultStatus = Status.WARN)
    void testCase02() {
    }

    @LintTest(
            name = "w_qcstatem_qcpds_lang_case",
            filename = "QcStmtEtsiValidCert03.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

    @LintTest(
            name = "w_qcstatem_qcpds_lang_case",
            filename = "QcStmtEtsiValidCert11.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

    @LintTest(
            name = "w_qcstatem_qcpds_lang_case",
            filename = "QcStmtEtsiValidAddLangCert13.pem",
            expectedResultStatus = Status.PASS)
    void testCase05() {
    }

    @LintTest(
            name = "w_qcstatem_qcpds_lang_case",
            filename = "QcStmtEtsiEsealValidCert02.pem",
            expectedResultStatus = Status.PASS)
    void testCase06() {
    }

    @LintTest(
            name = "w_qcstatem_qcpds_lang_case",
            filename = "QcStmtEtsiNoQcStatmentsCert22.pem",
            expectedResultStatus = Status.NA)
    void testCase07() {
    }
}