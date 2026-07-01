package com.packetanalyzer.rules;

public class BlockReason {
    public enum Type { IP, APP, DOMAIN, PORT }

    private final Type type;
    private final String detail;

    public BlockReason(Type type, String detail) {
        this.type = type;
        this.detail = detail;
    }

    public Type getType() {
        return type;
    }

    public String getDetail() {
        return detail;
    }
}
