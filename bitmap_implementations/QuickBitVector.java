/*
Copyright � 1999 CERN - European Organization for Nuclear Research.
Permission to use, copy, modify, distribute and sell this software and its documentation for any purpose 
is hereby granted without fee, provided that the above copyright notice appear in all copies and 
that both that copyright notice and this permission notice appear in supporting documentation. 
CERN makes no representations about the suitability of this software for any purpose. 
It is provided "as is" without expressed or implied warranty.
*/

/**
 * Implements quick non polymorphic non bounds checking low level bitvector operations.
 * Includes some operations that interpret sub-bitstrings as long integers.
 * <p>
 * <b>WARNING: Methods of this class do not check preconditions.</b>
 * Provided with invalid parameters these method may return (or set) invalid values without throwing any exception.
 * <b>You should only use this class when performance is critical and you are absolutely sure that indexes are within bounds.</b>
 * <p>	 
 * A bitvector is modelled as a long array, i.e. <tt>long[] bits</tt> holds bits of a bitvector.
 * Each long value holds 64 bits.
 * The i-th bit is stored in bits[i/64] at
 * bit position i % 64 (where bit position 0 refers to the least
 * significant bit and 63 refers to the most significant bit).
 *
 * @author wolfgang.hoschek@cern.ch
 * @version 1.0, 09/24/99
 * @see     BitVector
 * @see     BitMatrix
 * @see     java.util.BitSet
 */
package bitmap_implementations;

public class QuickBitVector extends Object {
	protected final static int ADDRESS_BITS_PER_UNIT = 6; // 64=2^6
	protected final static int BITS_PER_UNIT = 64; // = 1 << ADDRESS_BITS_PER_UNIT
	protected final static int BIT_INDEX_MASK = 63; // = BITS_PER_UNIT - 1;
	
	private static final long[] pows = precomputePows(); //precompute bitmasks for speed
/**
 * Makes this class non instantiable, but still inheritable.
 */
protected QuickBitVector() {
}
/**
 * Returns a bit mask with bits in the specified range set to 1, all the rest set to 0.
 * In other words, returns a bit mask having 0,1,2,3,...,64 bits set.
 * If <tt>to-from+1==0</tt> then returns zero (<tt>0L</tt>).
 * Precondition (not checked): <tt>to-from+1 >= 0 && to-from+1 <= 64</tt>.
 *
 * @param from index of start bit (inclusive)
 * @param to index of end bit (inclusive).
 * @return the bit mask having all bits between <tt>from</tt> and <tt>to</tt> set to 1.
 */
public static final long bitMaskWithBitsSetFromTo(long from, long to) {
	return pows[(int)(to-from+1)] << from; 
	// to - from + 1 是需要设置的位数。例如，如果 from = 3，to = 5，则位数为 3
	// pows 生成对应长度的掩码，例如pows[3] = 111
	// 左移：0b111 << 3 = 111000 左移相当于移到高位

	// This turned out to be slower:
	// 0xffffffffffffffffL == ~0L == -1L == all 64 bits set.
	// int width;
	// return (width=to-from+1) == 0 ? 0L : (0xffffffffffffffffL >>> (BITS_PER_UNIT-width)) << from;
}
/**
 * Changes the bit with index <tt>bitIndex</tt> in the bitvector <tt>bits</tt> to the "clear" (<tt>false</tt>) state.
 *
 * @param     bits   the bitvector.
 * @param     bitIndex   the index of the bit to be cleared.
 */
public static void clear(long[] bits, long bitIndex) {
	bits[(int)(bitIndex >> ADDRESS_BITS_PER_UNIT)] &= ~(1L << (bitIndex & BIT_INDEX_MASK));
}
/**
 * Returns from the bitvector the value of the bit with the specified index.
 * The value is <tt>true</tt> if the bit with the index <tt>bitIndex</tt> 
 * is currently set; otherwise, returns <tt>false</tt>.
 *
 * @param     bits   the bitvector.
 * @param     bitIndex   the bit index.
 * @return    the value of the bit with the specified index.
 */
public static boolean get(long[] bits, long bitIndex) {
	return ((bits[(int)(bitIndex >> ADDRESS_BITS_PER_UNIT)] & (1L << (bitIndex & BIT_INDEX_MASK))) != 0);
}
/**
 * Returns a long value representing bits of a bitvector from index <tt>from</tt> to index <tt>to</tt>.
 * Bits are returned as a long value with the return value having bit 0 set to bit <code>from</code>, ..., bit <code>to-from</code> set to bit <code>to</code>. 第 from 位对齐到返回值的 bit 0,第 to 位对齐到返回值的 bit (to-from)
 * All other bits of return value are set to 0.其他所有位（即不在 from 和 to 范围内的位）将被设置为 0
 * If <tt>from > to</tt> then returns zero (<tt>0L</tt>). 
 * Precondition (not checked): <tt>to-from+1 <= 64</tt>. 返回的位数不能超过 64，因为返回值是 long 类型（占 64 位）
 * @param bits the bitvector.
 * @param from index of start bit (inclusive).
 * @param to index of end bit (inclusive).
 * @return the specified bits as long value.
 */
public static long getLongFromTo(long[] bits, long from, long to) {
	//从一个 long 数组（bits）中提取指定范围（从 from 到 to）的位，并将返回为一个 long 类型的值
	if (from>to) return 0L;//如果 from > to，说明输入范围无效，直接返回 0。

	//计算开始和结束在哪一个 long 数组元素
	final int fromIndex = (int)(from >> ADDRESS_BITS_PER_UNIT); //equivalent to from/64
	final int toIndex = (int)(to >> ADDRESS_BITS_PER_UNIT);
	
	//计算起始和结束位在对应 long 数组元素中的偏移量
	final int fromOffset = (int)(from & BIT_INDEX_MASK); //equivalent to from%64
	final int toOffset = (int)(to & BIT_INDEX_MASK);
	//this is equivalent to the above, but slower:
	//final int fromIndex=from/BITS_PER_UNIT;
	//final int toIndex=to/BITS_PER_UNIT;
	//final int fromOffset=from%BITS_PER_UNIT;
	//final int toOffset=to%BITS_PER_UNIT;


	long mask;
	if (fromIndex==toIndex) { //range does not cross unit boundaries; value to retrieve is contained in one single long value.
		//如果 fromIndex == toIndex，表示所需位数都在同一个 long 元素中
		mask=bitMaskWithBitsSetFromTo(fromOffset, toOffset);//创建一个掩码 mask，仅保留 [fromOffset, toOffset] 范围的位
		return (bits[fromIndex]	& mask) >>> fromOffset;//用 bits[fromIndex] & mask 提取这些位(000[被提取的比特位]0000，最左边的0的个数=fromOffset);再右移 fromOffset 位对齐到最低位？
		
	}

	//range crosses unit boundaries; value to retrieve is spread over two long values.
	//get part from first long value
	//如果 fromIndex != toIndex，表示所需位数跨越两个 long 元素
	//从第一个 long 元素提取高位
	mask=bitMaskWithBitsSetFromTo(fromOffset, BIT_INDEX_MASK); //创建掩码保留 [fromOffset, 63] 范围的位
	final long x1=(bits[fromIndex] & mask) >>> fromOffset; //提取并右移 fromOffset 位
	
	//get part from second long value
	//从第二个 long 元素提取低位
	mask=bitMaskWithBitsSetFromTo(0, toOffset); //创建掩码保留 [0, toOffset] 范围的位
	final long x2=(bits[toIndex] & mask) << (BITS_PER_UNIT-fromOffset); //提取并左移到适当位置（64 - fromOffset）
	
	//combine
	return x1|x2; //将两部分用按位或操作合并
}
/**
Returns the index of the least significant bit in state "true".
Returns 32 if no bit is in state "true".
Examples: 
<pre>
0x80000000 --> 31
0x7fffffff --> 0
0x00000001 --> 0
0x00000000 --> 32
</pre>
*/
static public int leastSignificantBit(int value) {
	int i=-1;
	while (++i < 32 && (((1<<i) & value)) == 0);
	return i;
}
/**
 * Constructs a low level bitvector that holds <tt>size</tt> elements, with each element taking <tt>bitsPerElement</tt> bits.
 *
 * @param     size   the number of elements to be stored in the bitvector (must be >= 0).
 * @param     bitsPerElement   the number of bits one single element takes.
 * @return    a low level bitvector.
 */
	
public static long[] makeBitVector(long size, int bitsPerElement) {
	long nBits = size*bitsPerElement;
	int unitIndex = (int)((nBits-1) >> ADDRESS_BITS_PER_UNIT);
	long[] bitVector = new long[unitIndex + 1];
	return bitVector;
}
	/*
	1. long nBits = size * bitsPerElement;
	这行代码计算总比特数 nBits，它等于 size 和 bitsPerElement 的乘积。size 是向量中元素的数量，bitsPerElement 是每个元素占用的比特数。
 	例如，如果 size 是 1000，bitsPerElement 是 8，则 nBits 为 8000，表示需要 8000 个比特。
	2. int unitIndex = (int)((nBits - 1) >> ADDRESS_BITS_PER_UNIT);
	这里的 nBits - 1 是为了确保如果 nBits 正好是某个 long 数组的倍数时，索引会向上舍入。
	ADDRESS_BITS_PER_UNIT 是一个常量，表示每个 long 单元（long 类型通常为 64 位）的位数。
 	因此， (nBits - 1) >> ADDRESS_BITS_PER_UNIT 计算的是需要多少个 long 数组单元来存储这些比特。
	例如，如果 nBits 是 8000，而每个 long 单元有 64 位，(8000 - 1) >> 6 等于 124。即需要 125 个 long 单元来存储这些比特。
	3. long[] bitVector = new long[unitIndex + 1];
	根据计算的 unitIndex，创建一个新的 long[] 数组 bitVector。unitIndex + 1 是因为数组的索引是从 0 开始的，所以我们需要多一位来容纳所有的比特。
	4. return bitVector;
	返回创建好的 long[] 数组，它包含了足够的空间来存储 size * bitsPerElement 个比特。
	*/
	
/**
Returns the index of the most significant bit in state "true".
Returns -1 if no bit is in state "true".
Examples: 
<pre>
0x80000000 --> 31
0x7fffffff --> 30
0x00000001 --> 0
0x00000000 --> -1
</pre>
*/
static public int mostSignificantBit(int value) {
	int i=32;
	while (--i >=0 && (((1<<i) & value)) == 0);
	return i;
}
/**
 * Returns the index within the unit that contains the given bitIndex.
 */
protected static long offset(long bitIndex) {
	return bitIndex & BIT_INDEX_MASK;
	//equivalent to bitIndex%64
}
/**
 * Initializes a table with numbers having 1,2,3,...,64 bits set.
 * pows[i] has bits [0..i-1] set.
 * pows[64] == -1L == ~0L == has all 64 bits set --> correct.
 * to speedup calculations in subsequent methods.
 */
private static long[] precomputePows() {
	long[] pows=new long[BITS_PER_UNIT+1];
	long value = ~0L;
	for (int i=BITS_PER_UNIT+1; --i >= 1; ) {
		pows[i]=value >>> (BITS_PER_UNIT-i);
		//System.out.println((i)+":"+pows[i]);
	}
	pows[0]=0L;
	//System.out.println((0)+":"+pows[0]);
	return pows;

	//OLD STUFF
	/*
	for (int i=BITS_PER_UNIT+1; --i >= 0; ) {
		pows[i]=value;
		value = value >>> 1;
		System.out.println((i)+":"+pows[i]);
	}
	*/
	
	/*
	long[] pows=new long[BITS_PER_UNIT];
	for (int i=0; i<BITS_PER_UNIT-1; i++) {
		pows[i]=Math.round(Math.pow(2.0,i+1))-1;
		System.out.println((i)+":"+pows[i]);
	}
	pows[BITS_PER_UNIT-1] = ~0L;
	System.out.println((BITS_PER_UNIT-1)+":"+pows[BITS_PER_UNIT-1]);
	return pows;
	*/
}
/**
 * Sets the bit with index <tt>bitIndex</tt> in the bitvector <tt>bits</tt> to the state specified by <tt>value</tt>.
 *
 * @param     bits   the bitvector.
 * @param     bitIndex   the index of the bit to be changed.
 * @param     value   the value to be stored in the bit.
 */
public static void put(long[] bits, long bitIndex, boolean value) {	
	if (value) 
		set(bits, bitIndex);
	else 
		clear(bits, bitIndex);
}
/**
 * Sets bits of a bitvector from index <code>from</code> to index <code>to</code> to the bits of <code>value</code>.
 * Bit <code>from</code> is set to bit 0 of <code>value</code>, ..., bit <code>to</code> is set to bit <code>to-from</code> of <code>value</code>.
 * All other bits stay unaffected.
 * If <tt>from > to</tt> then does nothing.
 * Precondition (not checked): <tt>to-from+1 <= 64</tt>.
 *
 * @param bits the bitvector.
 * @param value the value to be copied into the bitvector.
 * @param from index of start bit (inclusive).
 * @param to index of end bit (inclusive).
 */
public static void putLongFromTo(long[] bits, long value, long from, long to) {
	if (from>to) return;
	
	final int fromIndex=(int)(from >> ADDRESS_BITS_PER_UNIT); //equivalent to from/64
	final int toIndex=(int)(to >> ADDRESS_BITS_PER_UNIT);
	final int fromOffset=(int)(from & BIT_INDEX_MASK); //equivalent to from%64
	final int toOffset=(int)(to & BIT_INDEX_MASK);
	/*
	this is equivalent to the above, but slower:
	int fromIndex=from/BITS_PER_UNIT;
	int toIndex=to/BITS_PER_UNIT;
	int fromOffset=from%BITS_PER_UNIT;	
	int toOffset=to%BITS_PER_UNIT;
	*/
	
	//make sure all unused bits to the left are cleared.
	long mask;
	mask=bitMaskWithBitsSetFromTo(to-from+1, BIT_INDEX_MASK);
	long cleanValue=value & (~mask);

	long shiftedValue;
	
	if (fromIndex==toIndex) { //range does not cross unit boundaries; should go into one single long value.
		shiftedValue=cleanValue << fromOffset;
		mask=bitMaskWithBitsSetFromTo(fromOffset, toOffset);
		bits[fromIndex] = (bits[fromIndex] & (~mask)) | shiftedValue;
		return;
		
	}

	//range crosses unit boundaries; value should go into two long values.
	//copy into first long value.
	shiftedValue=cleanValue << fromOffset;
	mask=bitMaskWithBitsSetFromTo(fromOffset, BIT_INDEX_MASK);
	bits[fromIndex] = (bits[fromIndex] & (~mask)) | shiftedValue;
	
	//copy into second long value.
	shiftedValue=cleanValue >>> (BITS_PER_UNIT - fromOffset);
	mask=bitMaskWithBitsSetFromTo(0, toOffset);
	bits[toIndex] = (bits[toIndex] & (~mask)) | shiftedValue;
}
/**
 * Changes the bit with index <tt>bitIndex</tt> in the bitvector <tt>bits</tt> to the "set" (<tt>true</tt>) state.
 *
 * @param     bits   the bitvector.
 * @param     bitIndex   the index of the bit to be set.
 */
public static void set(long[] bits, long bitIndex) { //在位数组 (bits) 中的特定位置 bitIndex 处设置位为 1
	bits[(int)(bitIndex >> ADDRESS_BITS_PER_UNIT)] |= 1L << (bitIndex & BIT_INDEX_MASK);           
}
/**
 * Returns the index of the unit that contains the given bitIndex.
 */
protected static long unit(long bitIndex) {
	return bitIndex >> ADDRESS_BITS_PER_UNIT;
	//equivalent to bitIndex/64
}
}
