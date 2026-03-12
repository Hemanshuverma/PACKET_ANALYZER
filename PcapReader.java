package com.dpi.pcap;

import com.dpi.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads network capture files in PCAP format (libpcap / Wireshark).
 *
 * PCAP file layout:
 *   [24-byte Global Header]
 *   [16-byte Packet Header] [N bytes Packet Data]
 *   [16-byte Packet Header] [N bytes Packet Data]
 *   ...
 */
public class PcapReader implements Closeable {

    // Magic numbers
    private static final int MAGIC_LITTLE_ENDIAN = 0xa1b2c3d4;
    private static final int MAGIC_BIG_ENDIAN    = 0xd4c3b2a1;
    private static final int MAGIC_NANO_LE       = 0xa1b23c4d;

    private DataInputStream in;
    private ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;
    private boolean nanoSecond  = false;
    private int linkType        = 0;  // 1 = Ethernet
    private long packetsRead    = 0;

    /**
     * Open a PCAP file and validate its global header.
     *
     * @param path  Path to the .pcap file
     * @throws IOException if the file cannot be opened or has an invalid header
     */
    public void open(String path) throws IOException {
        in = new DataInputStream(new BufferedInputStream(new FileInputStream(path)));
        readGlobalHeader();
    }

    private void readGlobalHeader() throws IOException {
        byte[] hdr = new byte[24];
        readFully(hdr);

        // Detect byte order from magic number (read as native int, bytes 0-3)
        int magicLE = ((hdr[0] & 0xFF))        |
                      ((hdr[1] & 0xFF) <<  8)  |
                      ((hdr[2] & 0xFF) << 16)  |
                      ((hdr[3] & 0xFF) << 24);

        if (magicLE == MAGIC_LITTLE_ENDIAN || magicLE == MAGIC_NANO_LE) {
            byteOrder  = ByteOrder.LITTLE_ENDIAN;
            nanoSecond = (magicLE == MAGIC_NANO_LE);
        } else if (magicLE == MAGIC_BIG_ENDIAN) {
            byteOrder  = ByteOrder.BIG_ENDIAN;
        } else {
            throw new IOException("Not a valid PCAP file (bad magic: 0x" +
                                  Integer.toHexString(magicLE) + ")");
        }

        ByteBuffer buf = ByteBuffer.wrap(hdr).order(byteOrder);
        buf.position(4);
        int versionMajor = buf.getShort() & 0xFFFF;
        int versionMinor = buf.getShort() & 0xFFFF;
        buf.getInt(); // timezone
        buf.getInt(); // timestamp accuracy
        buf.getInt(); // snap length
        linkType = buf.getInt();

        if (linkType != 1) {
            System.err.println("[PcapReader] Warning: link type " + linkType +
                               " is not Ethernet (1). Parsing may fail.");
        }
    }

    /**
     * Read the next packet from the file.
     *
     * @return the packet, or null at end of file
     * @throws IOException on read error
     */
    public RawPacket readNextPacket() throws IOException {
        byte[] phdr = new byte[16];
        int n = tryReadFully(phdr);
        if (n == 0) return null;  // EOF
        if (n != 16) throw new IOException("Truncated packet header");

        ByteBuffer buf = ByteBuffer.wrap(phdr).order(byteOrder);
        long tsSec  = buf.getInt()  & 0xFFFFFFFFL;
        long tsUsec = buf.getInt()  & 0xFFFFFFFFL;
        int inclLen = buf.getInt();   // bytes in file
        int origLen = buf.getInt();   // original length

        if (inclLen < 0 || inclLen > 65536) {
            throw new IOException("Unreasonable packet length: " + inclLen);
        }

        byte[] data = new byte[inclLen];
        readFully(data);
        packetsRead++;

        return new RawPacket(tsSec, tsUsec, origLen, data);
    }

    public long getPacketsRead() { return packetsRead; }
    public int  getLinkType()    { return linkType; }
    public ByteOrder getByteOrder() { return byteOrder; }

    @Override
    public void close() throws IOException {
        if (in != null) {
            in.close();
            in = null;
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private void readFully(byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) throw new EOFException("Unexpected end of PCAP file");
            off += n;
        }
    }

    /** Returns bytes read; 0 means clean EOF. */
    private int tryReadFully(byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) return off;
            off += n;
        }
        return off;
    }
}
