package de.mtg.jzlint.utils;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameException;
import inet.ipaddr.IPAddressString;

public final class IPUtils {

    private IPUtils() {
        // empty
    }

    private static final String[] reservedSegments = {
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "198.18.0.0/15",
            "2001:2::/48",
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "2001:db8::/32",
            "240.0.0.0/4",
            "0400::/6",
            "0800::/5",
            "1000::/4",
            "4000::/3",
            "6000::/3",
            "8000::/3",
            "a000::/3",
            "c000::/3",
            "e000::/4",
            "f000::/5",
            "f800::/6",
            "fe00::/9",
            "192.0.0.0/24",
            "2001::/23",
            "192.31.196.0/24",
            "192.175.48.0/24",
            "2001:4:112::/48",
            "2620:4f:8000::/48",
            "192.52.193.0/24",
            "2001:3::/32",
            "2001:20::/28",
            "0.0.0.0/8",
            "2002::/16",
            "64:ff9b::/96",
            "64:ff9b:1::/48",
            "192.0.0.8/32",
            "192.0.0.9/32",
            "2001:1::1/128",
            "192.0.0.10/32",
            "2001:1::2/128",
            "192.0.0.170/32",
            "192.0.0.171/32",
            "255.255.255.255/32",
            "100::/64",
            "2001::/32",
            "fc00::/7",
            "fe80::/10",
            "169.254.0.0/16",
            "255.0.0.0/8",
            "254.0.0.0/8",
            "253.0.0.0/8",
            "252.0.0.0/8",
            "251.0.0.0/8",
            "250.0.0.0/8",
            "249.0.0.0/8",
            "248.0.0.0/8",
            "247.0.0.0/8",
            "246.0.0.0/8",
            "245.0.0.0/8",
            "244.0.0.0/8",
            "243.0.0.0/8",
            "242.0.0.0/8",
            "241.0.0.0/8",
            "240.0.0.0/8",
            "239.0.0.0/8",
            "238.0.0.0/8",
            "237.0.0.0/8",
            "236.0.0.0/8",
            "235.0.0.0/8",
            "234.0.0.0/8",
            "233.0.0.0/8",
            "232.0.0.0/8",
            "231.0.0.0/8",
            "230.0.0.0/8",
            "229.0.0.0/8",
            "228.0.0.0/8",
            "227.0.0.0/8",
            "226.0.0.0/8",
            "225.0.0.0/8",
            "224.0.0.0/8",
            "ff00::/8"
    };

    public static boolean isIPInRange(String network, String address) {
        return new IPAddressString(network).contains(new IPAddressString(address));
    }

    public static boolean isReservedIP(String address) {
        for (String reservedSegment : reservedSegments) {
            if (isIPInRange(reservedSegment, address)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isIP(String address) {
        HostName hostname = new HostName(address);
        try {
            hostname.validate();
            return hostname.isAddress();
        } catch(HostNameException e) {
            return false;
        }
    }

}