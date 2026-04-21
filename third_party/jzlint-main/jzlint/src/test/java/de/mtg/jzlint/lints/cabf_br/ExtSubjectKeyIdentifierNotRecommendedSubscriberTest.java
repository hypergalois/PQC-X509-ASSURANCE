package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSubjectKeyIdentifierNotRecommendedSubscriberTest {

    @LintTest(
            name = "w_ext_subject_key_identifier_not_recommended_subscriber",
            filename = "warn_subject_key_identifier_not_recommended_subscriber.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_ext_subject_key_identifier_not_recommended_subscriber",
            filename = "pass_subject_key_identifier_not_recommended_subscriber.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "w_ext_subject_key_identifier_not_recommended_subscriber",
            filename = "ne_subject_key_identifier_not_recommended_subscriber.pem",
            expectedResultStatus = Status.NE)
    void testCase03() {
    }

}
