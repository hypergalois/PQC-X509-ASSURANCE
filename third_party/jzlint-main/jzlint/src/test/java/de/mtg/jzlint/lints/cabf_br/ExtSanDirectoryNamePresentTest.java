package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanDirectoryNamePresentTest {

    @LintTest(
            name = "e_ext_san_directory_name_present",
            filename = "SANDirectoryNameBeginning.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_directory_name_present",
            filename = "SANDirectoryNameEnd.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_san_directory_name_present",
            filename = "SANCaGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

}