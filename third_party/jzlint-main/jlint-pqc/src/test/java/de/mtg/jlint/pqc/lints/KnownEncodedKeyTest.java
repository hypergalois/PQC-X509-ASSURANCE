package de.mtg.jlint.pqc.lints;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.pqc.PQCCAExtension;
import de.mtg.jlint.pqc.util.PQCUtils;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class KnownEncodedKeyTest {

    @RegisterExtension
    static PQCCAExtension pqccaExtension = new PQCCAExtension();

    @Test
    void passTest() throws Exception {
        X509Certificate certificate = PQCCAExtension.createECCertificate();
        pqccaExtension.assertLintResult(LintResult.of(Status.PASS), new KnownEncodedKey(), certificate);
    }

    @Test
    void errorTest() throws Exception {

        //https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates-07
        String encodedPublicKey = """
                MIIFMjALBglghkgBZQMEAxEDggUhANeytHJUquDbReeTDUqY0sl9jxOX0Xidr6Fw
                JLMW6b7JT8mUbULxm3mnQTu6oz5xSctC7VEVaTrAQfrLmIretf4OHYYxGEmVtZLD
                l9IpTi4U+QqkFLo4JomaxD9MzKy8JumoMrlRGNXLQzy++WYLABOOCBf2HnYsonTD
                atVU6yKqwRYuSrAay6HjjE79j4C2WzM9D3LlXf5xzpweu5iJ58VhBsD9c4A6Kuz+
                r97XqjyyztpU0SvYzTanjPl1lDtHq9JeiArEUuV0LtHo0agq+oblkMdYwVrk0oQN
                kryhpQkPQElll/yn2LlRPxob2m6VCqqY3kZ1B9Sk9aTwWZIWWCw1cvYu2okFqzWB
                ZwxKAnd6M+DKcpX9j0/20aCjp2g9ZfX19/xg2gI+gmxfkhRMAvfRuhB1mHVT6pNn
                /NdtmQt/qZzUWv24g21D5Fn1GH3wWEeXCaAepoNZNfpwRgmQzT3BukAbqUurHd5B
                rGerMxncrKBgSNTE7vJ+4TqcF9BTj0MPLWQtwkFWYN54h32NirxyUjl4wELkKF9D
                GYRsRBJiQpdoRMEOVWuiFbWnGeWdDGsqltOYWQcf3MLN51JKe+2uVOhbMY6FTo/i
                svPt+slxkSgnCq/R5QRMOk/a/Z/zH5B4S46ORZYUSg2vWGUR09mWK56pWvGXtOX8
                YPKx7RXeOlvvX4m9x52RBR2bKBbnT6VFMe/cHL501EiFf0drzVjyHAtlOzt2pOB2
                plWaMCcYVVzGP3SFmqurkl8COGHKjND3utsocfZ9VTJtdFETWtRfShumkRj7ssij
                DuyTku8/l3Bmya3VxxDMZHsVFNIX2VjHAXw+kP0gwE5nS5BIbpNwoxoAHTL0c5ee
                SQZ0nn5Hf6C3RQj4pfI3gxK4PCW9OIygsP/3R4uvQrcWZ+2qyXxGsSlkPlhuWwVa
                DCEZRtTzbmdb7Vhg+gQqMV2YJhZNapI3w1pfv0lUkKW9TfJIuVxKrneEtgVnMWas
                QkW1tLCCoJ6TI+YvIHjFt2eDRG3v1zatOjcC1JsImESQCmGDM5e8RBmzDXqXoLOH
                wZEUdMTUG1PjKpd6y28Op122W7OeWecB52lX3vby1EVZwxp3EitSBOO1whnxaIsU
                7QvAuAGz5ugtzUPpwOn0F0TNmBW9G8iCDYuxI/BPrNGxtoXdWisbjbvz7ZM2cPCV
                oYC08ZLQixC4+rvfzCskUY4y7qCl4MkEyoRHgAg/OwzS0Li2r2e8NVuUlAJdx7Cn
                j6gOOi2/61EyiFHWB4GY6Uk2Ua54fsAlH5Irow6fUd9iptcnhM890gU5MXbfoySl
                Er2Ulwo23TSlFKhnkfDrNvAUWwmrZGUbSgMTsplhGiocSIkWJ1mHaKMRQGC6RENI
                bfUVIqHOiLMJhcIW+ObtF43VZ7MEoNTK+6iCooNC8XqaomrljbYwCD0sNY/fVmw/
                XWKkKFZ7yeqM6VyqDzVHSwv6jzOaJQq0388gg76O77wQVeGP4VNw7ssmBWbYP/Br
                IRquxDyim1TM0A+IFaJGXvC0ZRXMfkHzEk8J7/9zkwmrWLKaFFmgC85QOOk4yWeP
                cusOTuX9quZtn4Vz/Jf8QrSVn0v4th14Qz6GsDNdbpGRxNi/SHs5BcEIz9asJLDO
                t9y3z1H4TQ7Wh7lerrHFM8BvDZcCPZKnCCWDe1m6bLfU5WsKh8IDhiro8xW6WSXo
                7e+meTaaIgJ2YVHxapZfn4Hs52zAcLVYaeTbl4TPBcgwsyQsgxI=
                """;

        String cleanedKey = encodedPublicKey.replaceAll(" ", "").replaceAll("\\R", "");

        PrivateKey privateKey = pqccaExtension.getMldsaPrivateKey();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(100);
        X500Name issuerDN = new X500Name("CN=JZLint CA, C=DE");
        X500Name subjectDN = new X500Name("CN=PQC Certificate, C=DE");
        AlgorithmIdentifier signatureAID = new AlgorithmIdentifier(PQCUtils.ID_ML_DSA_65);

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(Base64.decode(cleanedKey));
        V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                spki, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, null);

        X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                PQCUtils.ID_ML_DSA_65.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

        pqccaExtension.assertLintResult(LintResult.of(Status.ERROR), new KnownEncodedKey(), certificate);
    }

}