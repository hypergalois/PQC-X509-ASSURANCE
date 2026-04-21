package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class GeneralizedTimeNotInZuluTest {

    @LintTest(
            name = "e_generalized_time_not_in_zulu",
            filename = "generalizedNotZulu.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_generalized_time_not_in_zulu",
            filename = "generalizedHasSeconds.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}