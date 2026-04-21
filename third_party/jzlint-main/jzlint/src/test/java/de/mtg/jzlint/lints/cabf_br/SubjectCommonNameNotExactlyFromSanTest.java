package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectCommonNameNotExactlyFromSanTest {

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "SANWithCNSeptember2021.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Pass - commonName in SAN.DNSNames")
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "SANIPv4Address.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Pass - common name and SAN.IPAddress, IPv4")
    void testCase02() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "SANIPv6Address.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Pass - common name and SAN.IPAddress, IPv6")
    void testCase03() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "SANIPv6AddressOne0Field.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Pass - IPv6 with a single 16-bit 0 field")
    void testCase04() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "MultipleCNsAllInSAN.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Pass - multiple CNs all appearing in SAN DNSNames")
    void testCase05() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "SANIPv6AddressChoiceInAbbreviation.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Error - IPv6 choice in abbreviation")
    void testCase06() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "CNWithoutSANSeptember2021.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - common name not in SAN.DNSNames")
    void testCase07() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "SANCaseNotMatchingCNSeptember2021.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - common name in SAN.DNSNames but case mismatch")
    void testCase08() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "SANIPv4AddressNotMatchingCommonName.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - common name not in SAN.IPAddresses, IPv4")
    void testCase09() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "SANIPv6AddressNotMatchingCommonName.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - common name not in SAN.IPAddresses, IPv6")
    void testCase10() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "SANIPv6AddressChoiceInAbbreviationInvalid.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - IPv6 choice in abbreviation, common name is invalid long form")
    void testCase11() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "CNPresentButEmpty.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error - certificate containing present but empty common names")
    void testCase12() {
    }

    @LintTest(
            name = "e_subject_common_name_not_exactly_from_san",
            filename = "SANWithMissingCN.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "NE - certificate issued before 21 August 2021")
    void testCase13() {
    }

}