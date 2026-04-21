package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class AlgorithmIdentifierImproperEncodingTest {

    @LintTest(
            name = "e_algorithm_identifier_improper_encoding",
            filename = "dsaCert.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Wrong subject public key algorithm identifier object algorithm",
            expectedResultDetails = "The encoded AlgorithmObjectIdentifier \"3082012b06072a8648ce3804013082011e02818100931d0880233aece9e2b816fb0e2daecc2b044e6131f401d784266b16fdf12992bb098f19f108ce4395f323859e7dfd19c88c2e75c976ca76c4ec61ec39efe745124683b726436926b79a36acac5ed9a02cd55bed1653912e10b5422823cf6d6b80057c88fe2da1fba521642142303a9f76c5cfcdf6d79dc4da1a6678f7d8cde3021500d13f595a85e4b55fe6f4c4b58090a979c03f212d02818029cc9723232468277f26e5148324661b0d2f54099cda8bbdd455f3f6faf33e72b99ed49b04358d82213d6ef4c3a70ed4f604d04814d60ff69c8307edaf3d49c596bebb0198797469d15422efcdb68a028c8aba632539576e9d5d077bd61b4abb6496cb58ea18e998c5123e551dc78a7c1bdd064dec12ef138be63a98159fa898\" inside the SubjectPublicKeyInfo field is not allowed")
    void testCase01() {
    }

    @LintTest(
            name = "e_algorithm_identifier_improper_encoding",
            filename = "publicKeyIsRSAWithCorrectEncoding.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Correct subject public key algorithm identifier for RSA")
    void testCase02() {
    }

    @LintTest(
            name = "e_algorithm_identifier_improper_encoding",
            filename = "publicKeyIsECCP256WithCorrectEncoding.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Correct subject public key algorithm identifier for P256")
    void testCase03() {
    }

    @LintTest(
            name = "e_algorithm_identifier_improper_encoding",
            filename = "publicKeyIsECCP384WithCorrectEncoding.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Correct subject public key algorithm identifier for P384")
    void testCase04() {
    }

    @LintTest(
            name = "e_algorithm_identifier_improper_encoding",
            filename = "publicKeyIsECCP521WithCorrectEncoding.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Correct subject public key algorithm identifier for P521")
    void testCase05() {
    }

    @LintTest(
            name = "e_algorithm_identifier_improper_encoding",
            filename = "publicKeyIsRSAExplicitNullMissing.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Public Key is RSA but the explicit NULL is missing from the parameters",
            expectedResultDetails = "The encoded AlgorithmObjectIdentifier \"300b06092a864886f70d010101\" inside the SubjectPublicKeyInfo field is not allowed")
    void testCase06() {
    }

}