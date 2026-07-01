package com.packetanalyzer.model;

public class RawPacket {
    private final Header header;
    private final byte[] data;

    public RawPacket(Header header, byte[] data) {
        this.header = header;
        this.data = data;
    }

    public Header getHeader() {
        return header;
    }

    public byte[] getData() {
        return data;
    }

    public static class Header {
        private final int tsSec;
        private final int tsUsec;
        private final int inclLen;
        private final int origLen;

        public Header(int tsSec, int tsUsec, int inclLen, int origLen) {
            this.tsSec = tsSec;
            this.tsUsec = tsUsec;
            this.inclLen = inclLen;
            this.origLen = origLen;
        }

        public int getTsSec() {
            return tsSec;
        }

        public int getTsUsec() {
            return tsUsec;
        }

        public int getInclLen() {
            return inclLen;
        }

        public int getOrigLen() {
            return origLen;
        }
    }
}
