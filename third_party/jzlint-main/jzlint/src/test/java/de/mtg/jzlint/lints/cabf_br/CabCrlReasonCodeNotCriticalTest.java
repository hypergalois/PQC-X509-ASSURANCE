package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintCRLTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CabCrlReasonCodeNotCriticalTest {

    @LintCRLTest(
            name = "e_cab_crl_reason_code_not_critical",
            filename = "crlReasonCodeCrit.pem",
            expectedResultStatus = Status.ERROR,
            crlDescription = "CRL reason code critical",
            expectedResultDetails = "MUST NOT be marked as critical")
    void testCase01() {
    }

    @LintCRLTest(
            name = "e_cab_crl_reason_code_not_critical",
            filename = "crlWithReasonCode5.pem",
            expectedResultStatus = Status.PASS,
            crlDescription = "CRL with reason code 5")
    void testCase02() {
    }

    @LintCRLTest(
            name = "e_cab_crl_reason_code_not_critical",
            filename = "crlEmpty.pem",
            expectedResultStatus = Status.NA,
            crlDescription = "CRL no revoked certificates")
    void testCase03() {
    }

}
