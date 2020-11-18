package andreas19.gemina4j;

/**
 * Version enum.
 */
public enum Version {
    /** version 1 */
    V1((byte) 0x8a, 16, 16),
    /** version 2 */
    V2((byte) 0x8b, 16, 32),
    /** version 3 */
    V3((byte) 0x8c, 24, 32),
    /** version 4 */
    V4((byte) 0x8d, 32, 32);

    private final byte versionByte;
    private final int encKeyLen;
    private final int macKeyLen;

    Version(byte versionByte, int encKeyLen, int macKeyLen) {
        this.versionByte = versionByte;
        this.encKeyLen = encKeyLen;
        this.macKeyLen = macKeyLen;
    }

    byte versionByte() {
        return this.versionByte;
    }

    int encKeyLen() {
        return this.encKeyLen;
    }

    int macKeyLen() {
        return this.macKeyLen;
    }

    static Version find(byte versionByte) {
        for (Version v : Version.values()) {
            if (v.versionByte == versionByte) return v;
        }
        return null;
    }

    public String toString() {
        return String.format("Version.%s: %#x, %d, %d",
                             this.name(),
                             this.versionByte,
                             this.encKeyLen,
                             this.macKeyLen);
    }
}
