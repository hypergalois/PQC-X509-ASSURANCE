package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class OcspIdPkixOcspNocheckExtNotIncludedServerAuthTest {


    // o1 --> EKU OCSPSigning set; o0 not set
    // s1 --> EKU serverAuth set, s0 not set
    // ep1 --> EKU emailProtection set, ep0 not set
    // a1 --> EKU anyExtendedKeyUsage set, a0 not set
    // nc1 --> noCheck set, nc0 not set

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s0ep0a0nc0.pem",
            expectedResultStatus = Status.NA)
    void testCase01() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s0ep0a0nc1.pem",
            expectedResultStatus = Status.NA)
    void testCase02() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s0ep0a1nc0.pem",
            expectedResultStatus = Status.NA)
    void testCase03() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s0ep0a1nc1.pem",
            expectedResultStatus = Status.NA)
    void testCase04() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s1ep0a0nc0.pem",
            expectedResultStatus = Status.NA)
    void testCase05() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s1ep0a0nc1.pem",
            expectedResultStatus = Status.NA)
    void testCase06() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s1ep0a1nc0.pem",
            expectedResultStatus = Status.NA)
    void testCase07() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s1ep0a1nc1.pem",
            expectedResultStatus = Status.NA)
    void testCase08() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s0ep0a0nc0.pem",
            expectedResultStatus = Status.NA)
    void testCase09() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s0ep0a0nc1.pem",
            expectedResultStatus = Status.NA)
    void testCase10() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s0ep0a1nc0.pem",
            expectedResultStatus = Status.ERROR)
    void testCase11() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s0ep0a1nc1.pem",
            expectedResultStatus = Status.PASS)
    void testCase12() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s1ep0a0nc0.pem",
            expectedResultStatus = Status.ERROR)
    void testCase13() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s1ep0a0nc1.pem",
            expectedResultStatus = Status.PASS)
    void testCase14() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s1ep0a1nc0.pem",
            expectedResultStatus = Status.ERROR)
    void testCase15() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s1ep0a1nc1.pem",
            expectedResultStatus = Status.PASS)
    void testCase16() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s0ep1a0nc0.pem",
            expectedResultStatus = Status.NA)
    void testCase17() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s0ep1a0nc1.pem",
            expectedResultStatus = Status.NA)
    void testCase18() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s0ep1a1nc0.pem",
            expectedResultStatus = Status.NA)
    void testCase19() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s0ep1a1nc1.pem",
            expectedResultStatus = Status.NA)
    void testCase20() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s1ep1a0nc0.pem",
            expectedResultStatus = Status.NA)
    void testCase21() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s1ep1a0nc1.pem",
            expectedResultStatus = Status.NA)
    void testCase22() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s1ep1a1nc0.pem",
            expectedResultStatus = Status.NA)
    void testCase23() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o0s1ep1a1nc1.pem",
            expectedResultStatus = Status.NA)
    void testCase24() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s0ep1a0nc0.pem",
            expectedResultStatus = Status.NA)
    void testCase25() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s0ep1a0nc1.pem",
            expectedResultStatus = Status.NA)
    void testCase26() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s0ep1a1nc0.pem",
            expectedResultStatus = Status.ERROR)
    void testCase27() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s0ep1a1nc1.pem",
            expectedResultStatus = Status.PASS)
    void testCase28() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s1ep1a0nc0.pem",
            expectedResultStatus = Status.ERROR)
    void testCase29() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s1ep1a0nc1.pem",
            expectedResultStatus = Status.PASS)
    void testCase30() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s1ep1a1nc0.pem",
            expectedResultStatus = Status.ERROR)
    void testCase31() {
    }

    @LintTest(
            name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
            filename = "o1s1ep1a1nc1.pem",
            expectedResultStatus = Status.PASS)
    void testCase32() {
    }

}