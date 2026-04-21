package de.mtg.jzlint.lints.etsi;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class QcstatemQctypeValidTest {

    @LintTest(
            name = "e_qcstatem_qctype_valid",
            filename = "QcStmtEtsiValidCert03.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_qcstatem_qctype_valid",
            filename = "QcStmtEtsiValidCert11.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_qcstatem_qctype_valid",
            filename = "QcStmtEtsiValidAddLangCert13.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

    @LintTest(
            name = "e_qcstatem_qctype_valid",
            filename = "QcStmtEtsiEsealValidCert02.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

    @LintTest(
            name = "e_qcstatem_qctype_valid",
            filename = "QcStmtEtsiNoQcStatmentsCert22.pem",
            expectedResultStatus = Status.NA)
    void testCase05() {
    }

}