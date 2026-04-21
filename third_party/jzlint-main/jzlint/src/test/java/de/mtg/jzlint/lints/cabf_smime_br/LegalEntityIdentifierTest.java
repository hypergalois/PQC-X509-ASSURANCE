package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class LegalEntityIdentifierTest {

    @LintTest(
            name = "e_legal_entity_identifier",
            filename = "smime/mailboxValidatedLegacyWithCommonName.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - mailbox validated, Legal Entity Identifier not present")
    void testCase01() {
    }

    @LintTest(
            name = "e_legal_entity_identifier",
            filename = "smime/mailbox_validated_with_lei.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - mailbox validated, Legal Entity Identifier present")
    void testCase02() {
    }

    @LintTest(
            name = "e_legal_entity_identifier",
            filename = "smime/individual_validated_with_lei.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - individual validated, Legal Entity Identifier present")
    void testCase03() {
    }

    @LintTest(
            name = "e_legal_entity_identifier",
            filename = "smime/organization_validated_with_lei_critical.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - organization validated, Legal Entity Identifier critical")
    void testCase04() {
    }

    @LintTest(
            name = "e_legal_entity_identifier",
            filename = "smime/organization_validated_with_lei_role.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - organization validated, Legal Entity Identifier Role present")
    void testCase05() {
    }

    @LintTest(
            name = "e_legal_entity_identifier",
            filename = "smime/sponsor_validated_with_lei_critical.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - sponsor validated, Legal Entity Identifier critical")
    void testCase06() {
    }

    @LintTest(
            name = "e_legal_entity_identifier",
            filename = "smime/sponsor_validated_with_lei_role_critical.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - sponsor validated, Legal Entity Identifier Role present")
    void testCase07() {
    }

}