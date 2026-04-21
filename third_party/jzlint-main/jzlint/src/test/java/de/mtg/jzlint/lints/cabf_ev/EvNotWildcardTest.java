package de.mtg.jzlint.lints.cabf_ev;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EvNotWildcardTest {

    @LintTest(
            name = "e_ev_not_wildcard",
            filename = "evWildcard.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ev_not_wildcard",
            filename = "evSubscriberNotWildCard.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_ev_not_wildcard",
            filename = "evSubscriberWildcardOnion.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

}