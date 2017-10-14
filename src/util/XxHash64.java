package util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public final class XxHash64 {
    private static final long PRIME64_1 = -7046029288634856825L;
    private static final long PRIME64_2 = -4417276706812531889L;
    private static final long PRIME64_3 = 1609587929392839161L;
    private static final long PRIME64_4 = -8796714831421723037L;
    private static final long PRIME64_5 = 2870177450012600261L;
    private final ByteBuffer mem64 = ByteBuffer.allocate(4 * 8);   /* buffer defined as U64 for alignment */
    private long total_len;
    private long v1;
    private long v2;
    private long v3;
    private long v4;
    private int memsize;

    public XxHash64(long seed) {
        reset(seed);
    }

    public XxHash64() {
        this(0);
    }

    public static final long hash64(final byte[] input, int offset, int length, long seed) {
        XxHash64 h = new XxHash64(seed);
        h.update(input, offset, length);
        return h.digest();
    }

    public static final long hash64(final ByteBuffer buf, long seed) {
        final byte[] array = buf.array();
        return hash64(array, buf.position(), buf.limit(), seed);
    }

    private static final long rotl64(final long x, final long r) {
        return ((x << r) | (x >>> (64 - r)));
    }

    private static final long round(final long acc, final long input) {
        long ac = input * PRIME64_2 + acc;
        ac = rotl64(ac, 31);
        return ac * PRIME64_1;
    }

    private static final long mergeRound(final long acc, final long va) {
        long v = round(0, va);
        long ac = acc ^ v;
        return ac * (PRIME64_1 + PRIME64_4);
    }

    public void reset(final long seed) {
        v1 = seed + PRIME64_1 + PRIME64_2;
        v2 = seed + PRIME64_2;
        v3 = seed + 0;
        v4 = seed - PRIME64_1;

        total_len = 0;
        Arrays.fill(mem64.array(), (byte) 0);
        memsize = 0;
        mem64.order(ByteOrder.nativeOrder());
    }

    public void update(ByteBuffer buf) {
        final byte[] array = buf.array();
        update(array, buf.position(), buf.limit());
    }

    public void update(byte[] input, int offset, int length) {
        int p = offset;
        final int end = p + length;
        final ByteBuffer inWrap = ByteBuffer.wrap(input);
        inWrap.order(ByteOrder.nativeOrder());
        final byte[] mem64Array = mem64.array();

        total_len += length;

        if (memsize + length < 32) {  /* fill in tmp buffer */
            System.arraycopy(input, offset, mem64Array, memsize, length);
            memsize += length;
            return;
        }

        if (memsize != 0) {   /* tmp buffer is full */
            System.arraycopy(input, offset, mem64Array, memsize, 32 - memsize);
            mem64.clear();
            v1 = round(v1, mem64.getLong());
            v2 = round(v2, mem64.getLong());
            v3 = round(v3, mem64.getLong());
            v4 = round(v4, mem64.getLong());
            p += 32 - memsize;
            memsize = 0;
        }

        if (p + 32 <= end) {
            final int limit = end - 32;
            inWrap.position(p);
            inWrap.limit(inWrap.capacity());
            do {
                v1 = round(v1, inWrap.getLong());
                p += 8;
                v2 = round(v2, inWrap.getLong());
                p += 8;
                v3 = round(v3, inWrap.getLong());
                p += 8;
                v4 = round(v4, inWrap.getLong());
                p += 8;
            } while (p <= limit);
        }

        if (p < end) {
            memsize = end - p;
            System.arraycopy(input, p, mem64Array, 0, memsize);
        }
    }

    public long digest() {
        int p = 0;
        final int end = memsize;
        long h64;
        final byte[] mem64Array = mem64.array();

        if (total_len >= 32) {
            h64 = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18);
            h64 = mergeRound(h64, v1);
            h64 = mergeRound(h64, v2);
            h64 = mergeRound(h64, v3);
            h64 = mergeRound(h64, v4);
        } else {
            h64 = v3 + PRIME64_5;
        }

        h64 += total_len;

        mem64.clear();
        while (p + 8 <= end) {
            final long k1 = round(0, mem64.getLong());
            h64 ^= k1;
            h64 = rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
            p += 8;
        }

        mem64.position(p);
        if (p + 4 <= end) {
            h64 ^= mem64.getInt() * PRIME64_1;
            h64 = rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
            p += 4;
        }

        while (p < end) {
            h64 ^= mem64Array[p] * PRIME64_5;
            h64 = rotl64(h64, 11) * PRIME64_1;
            p++;
        }

        h64 ^= h64 >>> 33;
        h64 *= PRIME64_2;
        h64 ^= h64 >>> 29;
        h64 *= PRIME64_3;
        h64 ^= h64 >>> 32;

        return h64;
    }

}
