package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SanDnsNameDuplicateTest {

    @LintTest(
            name = "n_san_dns_name_duplicate",
            filename = "SANDNSDuplicate.pem",
            expectedResultStatus = Status.NOTICE)
    void testCase01() {
    }

}