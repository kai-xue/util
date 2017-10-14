package util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public final class XxHash32 {
    private static final int PRIME32_1 = -1640531535;
    private static final int PRIME32_2 = -2048144777;
    private static final int PRIME32_3 = -1028477379;
    private static final int PRIME32_4 = 668265263;
    private static final int PRIME32_5 = 374761393;
    private final ByteBuffer mem32 = ByteBuffer.allocate(4 * 4);
    private int total_len_32;
    private boolean large_len = false;
    private int v1;
    private int v2;
    private int v3;
    private int v4;
    private int memsize;

    public XxHash32(int seed) {
        reset(seed);
    }

    public XxHash32() {
        this(0);
    }

    public static final int hash32(final byte[] input, int offset, final int length, final int seed) {
        XxHash32 h = new XxHash32(seed);
        h.update(input, offset, length);
        return h.digest();
    }

    public static final int hash32(final ByteBuffer buf, final int seed) {
        final byte[] array = buf.array();
        return hash32(array, buf.position(), buf.limit(), seed);
    }

    private static final int rotl32(final int x, final int r) {
        return ((x << r) | (x >>> (32 - r)));
    }

    private static final int round(final int seed, final int input) {
        int sd = input * PRIME32_2 + seed;
        sd = rotl32(sd, 13);
        return sd * PRIME32_1;
    }

    public void reset(final int seed) {
        v1 = seed + PRIME32_1 + PRIME32_2;
        v2 = seed + PRIME32_2;
        v3 = seed + 0;
        v4 = seed - PRIME32_1;
        total_len_32 = 0;
        large_len = false;
        Arrays.fill(mem32.array(), (byte) 0);
        memsize = 0;
        mem32.order(ByteOrder.nativeOrder());
    }

    public void update(final ByteBuffer buf) {
        final byte[] array = buf.array();
        update(array, buf.position(), buf.limit());
    }

    public void update(final byte[] input, final int offset, final int length) {
        int p = offset;
        final int end = p + length;
        final byte[] mem32Array = mem32.array();
        final ByteBuffer inWrap = ByteBuffer.wrap(input);
        inWrap.order(ByteOrder.nativeOrder());

        total_len_32 += length;
        large_len |= (length >= 16) | (total_len_32 >= 16);

        if (memsize + length < 16) {
            System.arraycopy(input, offset, mem32Array, memsize, length);
            memsize += length;
            return;
        }

        if (memsize != 0) {
            System.arraycopy(input, offset, mem32Array, memsize, 16 - memsize);
            mem32.clear();

            v1 = round(v1, mem32.getInt());
            v2 = round(v2, mem32.getInt());
            v3 = round(v3, mem32.getInt());
            v4 = round(v4, mem32.getInt());

            p += 16 - memsize;
            memsize = 0;
        }

        if (p <= end - 16) {
            final int limit = end - 16;
            inWrap.position(p);
            inWrap.limit(inWrap.capacity());
            do {
                v1 = round(v1, inWrap.getInt());
                p += 4;
                v2 = round(v2, inWrap.getInt());
                p += 4;
                v3 = round(v3, inWrap.getInt());
                p += 4;
                v4 = round(v4, inWrap.getInt());
                p += 4;
            } while (p <= limit);
        }

        if (p < end) {
            memsize = end - p;
            System.arraycopy(input, p, mem32Array, 0, memsize);
        }
    }

    public int digest() {
        int p = 0;
        byte[] array = mem32.array();
        final int end = memsize;
        int h32;

        if (large_len) {
            h32 = rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18);
        } else {
            h32 = v3 /* == seed */ + PRIME32_5;
        }

        h32 += total_len_32;

        mem32.position(p);
        while (p + 4 <= end) {
            h32 += mem32.getInt() * PRIME32_3;
            h32 = rotl32(h32, 17) * PRIME32_4;
            p += 4;
        }

        while (p < end) {
            h32 += array[p] * PRIME32_5;
            h32 = rotl32(h32, 11) * PRIME32_1;
            p++;
        }

        h32 ^= h32 >>> 15;
        h32 *= PRIME32_2;
        h32 ^= h32 >>> 13;
        h32 *= PRIME32_3;
        h32 ^= h32 >>> 16;

        return h32;
    }

}
