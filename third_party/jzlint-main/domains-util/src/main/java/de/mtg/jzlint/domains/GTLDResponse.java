package de.mtg.jzlint.domains;

import java.util.ArrayList;
import java.util.List;

public class GTLDResponse {

    List<GTLD> gTLDs = new ArrayList<>();

    public GTLDResponse() {
        // empty
    }

    public List<GTLD> getgTLDs() {
        return gTLDs;
    }

    public void setgTLDs(List<GTLD> gTLDs) {
        this.gTLDs = gTLDs;
    }

}
