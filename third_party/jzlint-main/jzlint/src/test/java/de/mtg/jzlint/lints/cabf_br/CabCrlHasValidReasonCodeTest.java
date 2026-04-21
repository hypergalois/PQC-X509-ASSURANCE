package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintCRLTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CabCrlHasValidReasonCodeTest {

    @LintCRLTest(
            name = "e_cab_crl_has_valid_reason_code",
            filename = "crlWithReasonCode0.pem",
            expectedResultStatus = Status.ERROR,
            crlDescription = "CRL with reason code 0",
            expectedResultDetails = "The reason code CRL entry extension SHOULD be absent instead of using the unspecified")
    void testCase01() {
    }

    @LintCRLTest(
            name = "e_cab_crl_has_valid_reason_code",
            filename = "crlWithReasonCode2.pem",
            expectedResultStatus = Status.ERROR,
            crlDescription = "CRL with reason code 2",
            expectedResultDetails = "Reason code not included in BR: 7.2.2")
    void testCase02() {
    }

    @LintCRLTest(
            name = "e_cab_crl_has_valid_reason_code",
            filename = "crlWithReasonCode5.pem",
            expectedResultStatus = Status.PASS,
            crlDescription = "CRL with reason code 5")
    void testCase03() {
    }

    @LintCRLTest(
            name = "e_cab_crl_has_valid_reason_code",
            filename = "crlWithReasonCode7.pem",
            expectedResultStatus = Status.ERROR,
            crlDescription = "CRL with reason code 7",
            expectedResultDetails = "Reason code not included in BR: 7.2.2")
    void testCase04() {
    }

    @LintCRLTest(
            name = "e_cab_crl_has_valid_reason_code",
            filename = "crlThisUpdate20230505.pem",
            expectedResultStatus = Status.NE,
            crlDescription = "CRL thisUpdate before enforcement")
    void testCase05() {
    }

}
