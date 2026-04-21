package de.mtg.jzlint.lints.etsi;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class QcstatemQctypeWebTest {

    @LintTest(
            name = "w_qcstatem_qctype_web",
            filename = "QcStmtEtsiValidCert11.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "w_qcstatem_qctype_web",
            filename = "QcStmtEtsiEsealValidCert02.pem",
            expectedResultStatus = Status.WARN)
    void testCase02() {
    }

    @LintTest(
            name = "w_qcstatem_qctype_web",
            filename = "QcStmtEtsiNoQcStatmentsCert22.pem",
            expectedResultStatus = Status.NA)
    void testCase03() {
    }

}