package com.dpi.pcap;

import com.dpi.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Writes network packets to a PCAP file.
 * Always writes little-endian PCAP format (compatible with Wireshark).
 */
public class PcapWriter implements Closeable {

    private static final int MAGIC      = 0xa1b2c3d4;
    private static final int LINK_ETHER = 1;

    private DataOutputStream out;
    private long packetsWritten = 0;

    /**
     * Open / create a PCAP output file.
     *
     * @param path  Destination file path
     * @throws IOException on I/O error
     */
    public void open(String path) throws IOException {
        out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(path)));
        writeGlobalHeader();
    }

    private void writeGlobalHeader() throws IOException {
        // 24-byte PCAP global header (little-endian)
        ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(MAGIC);
        buf.putShort((short) 2);        // version major
        buf.putShort((short) 4);        // version minor
        buf.putInt(0);                   // timezone (UTC)
        buf.putInt(0);                   // timestamp accuracy
        buf.putInt(65535);               // snap length
        buf.putInt(LINK_ETHER);          // link type: Ethernet
        out.write(buf.array());
    }

    /**
     * Write a single packet to the output file.
     *
     * @param packet  The raw packet (with original timestamps)
     * @throws IOException on I/O error
     */
    public void writePacket(RawPacket packet) throws IOException {
        // 16-byte packet header
        ByteBuffer hdr = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        hdr.putInt((int)(packet.tsSec   & 0xFFFFFFFFL));
        hdr.putInt((int)(packet.tsUsec  & 0xFFFFFFFFL));
        hdr.putInt(packet.data.length);   // incl_len
        hdr.putInt(packet.origLen);       // orig_len
        out.write(hdr.array());
        out.write(packet.data);
        packetsWritten++;
    }

    public long getPacketsWritten() { return packetsWritten; }

    @Override
    public void close() throws IOException {
        if (out != null) {
            out.flush();
            out.close();
            out = null;
        }
    }
}
