package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RootCaBasicConstraintsPathLenConstraintFieldPresentTest {

    @LintTest(
            name = "w_root_ca_basic_constraints_path_len_constraint_field_present",
            filename = "rootCaMaxPathLenPresent.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_root_ca_basic_constraints_path_len_constraint_field_present",
            filename = "rootCaMaxPathLenMissing.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}