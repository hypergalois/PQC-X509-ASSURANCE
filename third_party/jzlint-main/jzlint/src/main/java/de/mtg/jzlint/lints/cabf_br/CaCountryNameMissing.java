package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


/************************************************
 BRs: 7.1.2.1e
 The	Certificate	Subject	MUST contain the following:
 -	countryName	(OID 2.5.4.6).
 This field MUST	contain	the	two-letter	ISO	3166-1 country code	for	the country
 in which the CA’s place	of business	is located.
 ************************************************/

@Lint(
        name = "e_ca_country_name_missing",
        description = "Root and Subordinate CA certificates MUST have a countryName present in subject information",
        citation = "BRs: 7.1.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class CaCountryNameMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> countryName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.countryName.getId());

        if (Utils.componentNameIsEmpty(countryName)) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isCA(certificate);
    }

}
