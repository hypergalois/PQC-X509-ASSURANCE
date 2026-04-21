package de.mtg.jzlint.utils;

import java.util.Optional;

public final class StringUtils {

    private StringUtils() {
        // empty
    }

    public static Optional<String> getAfterLastDot(String input) {

        if (input == null || !input.contains(".")) {
            return Optional.empty();
        }

        if (input.endsWith(".")) {
            return Optional.empty();
        }

        int lastDotIndex = input.lastIndexOf(".");

        return Optional.of(input.substring(lastDotIndex + 1));
    }


    public static Optional<String> getAfterFirstDot(String input) {

        if (input == null || !input.contains(".")) {
            return Optional.empty();
        }

        if (input.endsWith(".")) {
            return Optional.empty();
        }

        int firstDotIndex = input.indexOf(".");

        return Optional.of(input.substring(firstDotIndex + 1));
    }

    public static Optional<String> getBeforeLastDot(String input) {

        if (input == null || !input.contains(".")) {
            return Optional.empty();
        }

        int lastDotIndex = input.lastIndexOf(".");

        return Optional.of(input.substring(0, lastDotIndex));
    }

    public static Optional<String> getWithoutEnding(String input, String ending) {

        if (input == null || ending == null) {
            return Optional.empty();
        }

        if (!input.endsWith(ending)) {
            return Optional.empty();
        }

        return Optional.of(input.substring(0, input.length() - ending.length()));
    }


    public static String removeAllTrailingDots(String input) {

        if (input == null || input.isEmpty()) {
            return input;
        }

        while (input.endsWith(".")) {
            input = input.substring(0, input.length() - 1);
        }

        return input;
    }


    public static String removeAllLeadingDots(String input) {

        if (input == null || input.isEmpty()) {
            return input;
        }

        while (input.startsWith(".")) {
            input = input.substring(1);
        }

        return input;
    }

}
