package de.mtg.jzlint.lints.cabf_ev;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.DateUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_onion_subject_validity_time_too_large",
        description = "certificates with .onion names can not be valid for more than 15 months",
        citation = "EVGs: Appendix F",
        source = Source.CABF_EV_GUIDELINES,
        effectiveDate = EffectiveDate.OnionOnlyEVDate)
public class EOnionSubjectValidityTimeTooLarge implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        int validityInMonths = DateUtils.getValidityInMonths(certificate);

        if (validityInMonths > 15) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        if (!Utils.isSubscriberCert(certificate)) {
            return false;
        }

//        if (!EVUtils.isEV(certificate)) {
//            return false;
//        }

        try {
            List<String> commonNames = Utils.getAllAttributeValuesInSubject(certificate, X509ObjectIdentifiers.commonName.getId());
            List<String> dnsNames = Utils.getDNSNames(certificate);
            commonNames.addAll(dnsNames);

            for (String value : commonNames) {
                if (value.endsWith(".onion")) {
                    return true;
                }
            }
        } catch (CertificateEncodingException | IOException ex) {
            throw new RuntimeException(ex);
        }
        return false;
    }

}
