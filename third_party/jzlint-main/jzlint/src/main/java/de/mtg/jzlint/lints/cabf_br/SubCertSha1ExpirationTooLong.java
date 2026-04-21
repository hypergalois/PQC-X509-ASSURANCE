package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.DateUtils;
import de.mtg.jzlint.utils.Utils;

/***************************************************************************************************************
 Effective 16 January 2015, CAs SHOULD NOT issue Subscriber Certificates utilizing the SHA-1 algorithm with
 an Expiry Date greater than 1 January 2017 because Application Software Providers are in the process of
 deprecating and/or removing the SHA-1 algorithm from their software, and they have communicated that
 CAs and Subscribers using such certificates do so at their own risk.
 ****************************************************************************************************************/

@Lint(
        name = "w_sub_cert_sha1_expiration_too_long",
        description = "Subscriber certificates using the SHA-1 algorithm SHOULD NOT have an expiration date later than 1 Jan 2017",
        citation = "BRs: 7.1.3",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_2_1_Date)
public class SubCertSha1ExpirationTooLong implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        ZonedDateTime sha1SunsetDate = ZonedDateTime.of(2017, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"));

        if (DateUtils.expiresAfter(certificate, sha1SunsetDate)) {
            return LintResult.of(Status.WARN);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {


        List<String> algorithms = Arrays.asList(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(),
                OIWObjectIdentifiers.dsaWithSHA1.getId(), X9ObjectIdentifiers.ecdsa_with_SHA1.getId());

        String signatureAlgorithm = certificate.getSigAlgOID();

        return (!Utils.isCA(certificate) && algorithms.contains(signatureAlgorithm));
    }

}