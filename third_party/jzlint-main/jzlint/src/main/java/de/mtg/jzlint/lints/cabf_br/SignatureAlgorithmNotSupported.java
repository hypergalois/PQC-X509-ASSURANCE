package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_signature_algorithm_not_supported",
        description = "Certificates MUST meet the following requirements for algorithm Source: SHA-1*, SHA-256, SHA-384, SHA-512",
        citation = "BRs: 6.1.5",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.ZERO)
public class SignatureAlgorithmNotSupported implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<String> passAlgorithms = Arrays.asList(
                PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(),
                PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(),
                PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(),
                NISTObjectIdentifiers.dsa_with_sha256.getId(),
                X9ObjectIdentifiers.ecdsa_with_SHA256.getId(),
                X9ObjectIdentifiers.ecdsa_with_SHA384.getId(),
                X9ObjectIdentifiers.ecdsa_with_SHA512.getId(),
                PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(),
                OIWObjectIdentifiers.dsaWithSHA1.getId(),
                X9ObjectIdentifiers.ecdsa_with_SHA1.getId()
        );

        String signatureOID = certificate.getSigAlgOID();

        if (passAlgorithms.contains(signatureOID)) {
            return LintResult.of(Status.PASS);
        }
        if (PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(signatureOID)) {
            return LintResult.of(Status.WARN);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }


}
