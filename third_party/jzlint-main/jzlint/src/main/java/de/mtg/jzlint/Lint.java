package de.mtg.jzlint;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface Lint {

    String name();

    String description();

    String citation();

    EffectiveDate effectiveDate();

    IneffectiveDate ineffectiveDate() default IneffectiveDate.EMPTY;

    Source source();

}

