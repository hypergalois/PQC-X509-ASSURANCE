package de.mtg.jzlint.lints.cabf_ev;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.EVUtils;
import de.mtg.jzlint.utils.Utils;


@Lint(
        name = "e_ev_san_ip_address_present",
        description = "The Subject Alternate Name extension MUST contain only 'dnsName' name types.",
        citation = "CABF EV Guidelines 1.7.8 Section 9.8.1",
        source = Source.CABF_EV_GUIDELINES,
        effectiveDate = EffectiveDate.ZERO)
public class EvSanIpAddressPresent implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawSAN = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

        try {
            List<GeneralName> allGeneralNames = Utils.getAllGeneralNames(rawSAN);
            boolean notDNSFound = allGeneralNames.stream().anyMatch(generalName -> generalName.getTagNo() != 2);

            if (notDNSFound) {
                return LintResult.of(Status.ERROR);
            }
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return EVUtils.isEV(certificate);
    }

}
