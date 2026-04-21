package de.mtg.jzlint.utils;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseBytes;

public final class DateUtils {

    public static final String UTC = "UTC";
    public static final long NUMBER_OF_SECONDS_IN_DAY = 86400L;

    private DateUtils() {
        // empty
    }

    public static boolean isIssuedOnOrAfter(ZonedDateTime time, ZonedDateTime referenceDate) {
        return !time.isBefore(referenceDate);
    }

    public static boolean isIssuedOnOrAfter(X509Certificate certificate, ZonedDateTime date) {
        ZonedDateTime notBefore = getNotBefore(certificate);
        return !notBefore.isBefore(date);
    }

    public static boolean isIssuedOnOrAfter(X509CRL crl, ZonedDateTime date) {
        ZonedDateTime notBefore = getThisUpdate(crl);
        return !notBefore.isBefore(date);
    }

    public static boolean isProducedOnOrAfter(OCSPResponse ocspResponse, ZonedDateTime date) {
        return !getProducedAt(ocspResponse).isBefore(date);
    }

    public static boolean isIssuedBefore(X509Certificate certificate, ZonedDateTime date) {
        ZonedDateTime notBefore = getNotBefore(certificate);
        return notBefore.isBefore(date);
    }

    public static boolean expiresBefore(X509Certificate certificate, ZonedDateTime date) {
        ZonedDateTime notAfter = getNotAfter(certificate);
        return notAfter.isBefore(date);
    }

    public static boolean expiresOnOrAfter(X509Certificate certificate, ZonedDateTime date) {
        ZonedDateTime notAfter = getNotAfter(certificate);
        return !notAfter.isBefore(date);
    }

    public static boolean expiresAfter(X509Certificate certificate, ZonedDateTime date) {
        ZonedDateTime notAfter = getNotAfter(certificate);
        return notAfter.isAfter(date);
    }

    public static ZonedDateTime getNotBefore(X509Certificate certificate) {
        return ZonedDateTime.ofInstant(certificate.getNotBefore().toInstant(), ZoneId.of(UTC));
    }

    public static ZonedDateTime getThisUpdate(X509CRL crl) {
        return ZonedDateTime.ofInstant(crl.getThisUpdate().toInstant(), ZoneId.of(UTC));
    }

    public static ZonedDateTime getProducedAt(OCSPResponse ocspResponse) {

        OCSPResponse response = OCSPResponse.getInstance(ocspResponse);

        ResponseBytes responseBytes = response.getResponseBytes();
        BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(responseBytes.getResponse().getOctets());

        ASN1GeneralizedTime producedAt = basicOCSPResponse.getTbsResponseData().getProducedAt();
        try {
            return ZonedDateTime.ofInstant(producedAt.getDate().toInstant(), ZoneId.of(UTC));
        } catch (ParseException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static ZonedDateTime getNotAfter(X509Certificate certificate) {
        return ZonedDateTime.ofInstant(certificate.getNotAfter().toInstant(), ZoneId.of(UTC));
    }

    public static int getValidityInDays(X509Certificate certificate) {

        ZonedDateTime notBefore = getNotBefore(certificate);
        ZonedDateTime notAfter = getNotAfter(certificate);

        return getValidityInDays(notAfter.toEpochSecond(), notBefore.toEpochSecond());
    }

    public static int getValidityInDaysBeforeSC31(X509Certificate certificate) {

        ZonedDateTime notBefore = getNotBefore(certificate);
        ZonedDateTime notAfter = getNotAfter(certificate);

        return getValidityInDaysBeforeSC31(notAfter, notBefore);
    }

    public static int getValidityInMonths(X509Certificate certificate) {
        ZonedDateTime notBefore = getNotBefore(certificate);
        ZonedDateTime notAfter = getNotAfter(certificate);
        return getValidityInMonths(notAfter, notBefore);
    }

    public static int getValidityInMonthsBeforeSC31(X509Certificate certificate) {
        ZonedDateTime notBefore = getNotBefore(certificate);
        ZonedDateTime notAfter = getNotAfter(certificate);
        return getValidityInMonthsBeforeSC31(notAfter, notBefore);
    }

    public static int getValidityInDays(long end, long start) {
        return (int) Math.floorDiv((end - start), NUMBER_OF_SECONDS_IN_DAY) + 1;
    }

    public static int getValidityInDaysBeforeSC31(ZonedDateTime end, ZonedDateTime start) {

        int rfcNumberOfDays = getValidityInDays(end.toEpochSecond(), start.toEpochSecond());
        int days = rfcNumberOfDays - 2;

        while (start.plusDays(days).isBefore(end)) {
            days += 1;
        }
        return days;
    }

    public static int getValidityInMonths(ZonedDateTime end, ZonedDateTime start) {
        int days = getValidityInDays(end.toEpochSecond(), start.toEpochSecond());
        int months = Math.floorDiv(days, 32);
        while (!start.plusMonths(months).isAfter(end)) {
            months += 1;
        }
        return months;
    }

    public static int getValidityInMonthsBeforeSC31(ZonedDateTime end, ZonedDateTime start) {
        int days = getValidityInDays(end.toEpochSecond(), start.toEpochSecond());
        int months = Math.floorDiv(days, 32);
        while (start.plusMonths(months).isBefore(end)) {
            months += 1;
        }
        return months;
    }

}