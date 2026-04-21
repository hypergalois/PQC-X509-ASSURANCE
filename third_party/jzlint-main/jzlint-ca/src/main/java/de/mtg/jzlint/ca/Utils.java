package de.mtg.jzlint.ca;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public final class Utils {

    public static void handleIssuedCertificate(
            String[] args,
            String nameDER,
            X509Certificate testCertificate,
            String namePEM,
            StringBuilder zlintTestVectors,
            String lintResult,
            String description)
            throws IOException, CertificateEncodingException {
        Files.write(Paths.get(nameDER), testCertificate.getEncoded());
        System.out.printf("openssl x509 -inform DER -outform PEM -in %s -out %s -text%n", nameDER, namePEM);

        if (args != null && args.length > 0) {
            System.out.printf("cp %s %s%n", namePEM, args[0]);
        }

        zlintTestVectors.append("{");
        zlintTestVectors.append(System.lineSeparator());
        zlintTestVectors.append("Name: \"");
        zlintTestVectors.append(description);
        zlintTestVectors.append("\",");
        zlintTestVectors.append(System.lineSeparator());
        zlintTestVectors.append("InputFilename: \"");
        zlintTestVectors.append(namePEM);
        zlintTestVectors.append("\",");
        zlintTestVectors.append(System.lineSeparator());
        zlintTestVectors.append("ExpectedResult: lint.");
        zlintTestVectors.append(lintResult);
        zlintTestVectors.append(",");
        zlintTestVectors.append(System.lineSeparator());
        zlintTestVectors.append("},");
        zlintTestVectors.append(System.lineSeparator());

    }

}