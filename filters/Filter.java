package filters;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import bitmap_implementations.Bitmap;

public abstract class Filter {
	
	HashType hash_type;
	
	abstract boolean rejuvenate(long key);
	abstract boolean expand();
	protected abstract long _delete(long large_hash);
	abstract protected boolean _insert(long large_hash, boolean insert_only_if_no_match);
	abstract protected boolean _search(long large_hash);

	int num_logical_entries = 0;
	
	public int get_num_logical_entries() {
		return num_logical_entries;
	}

	public long delete(long input) {
		long slot = _delete(get_hash(input));
		if (slot >= 0) {
			num_logical_entries--;
		}
		return slot;
	}

	public long delete(String input) {
		ByteBuffer input_buffer = ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8));
		long slot =  _delete(HashFunctions.xxhash(input_buffer));
		if (slot >= 0) {
			num_logical_entries--;
		}
		return slot;
	}

	public long delete(byte[] input) {
		ByteBuffer input_buffer = ByteBuffer.wrap(input);
		long slot =  _delete(HashFunctions.xxhash(input_buffer));
		if (slot >= 0) {
			num_logical_entries--;
		}
		return slot;
	}
	
	public boolean insert(long input, boolean insert_only_if_no_match) {		
		long hash = get_hash(input);
		boolean success = _insert(hash, insert_only_if_no_match);
		if (success) {
			num_logical_entries++;
		}
		return success;
	}

	public boolean insert(String input, boolean insert_only_if_no_match) {
		ByteBuffer input_buffer = ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8));
		boolean success =  _insert(HashFunctions.xxhash(input_buffer), insert_only_if_no_match);
		if (success) {
			num_logical_entries++;
		}
		return success;
	}

	public boolean insert(byte[] input, boolean insert_only_if_no_match) {
		ByteBuffer input_buffer = ByteBuffer.wrap(input);
		boolean success =  _insert(HashFunctions.xxhash(input_buffer), insert_only_if_no_match);
		if (success) {
			num_logical_entries++;
		}
		return success;
	}
	
	public boolean search(long input) {
		return _search(get_hash(input));
	}

	public boolean search(String input) {
		ByteBuffer input_buffer = ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8));
		return _search(HashFunctions.xxhash(input_buffer));
	}

	public boolean search(byte[] input) {
		ByteBuffer input_buffer = ByteBuffer.wrap(input);
		return _search(HashFunctions.xxhash(input_buffer));
	}
	
	long get_hash(long input) {
		long hash = 0;
		if (hash_type == HashType.arbitrary) {
			hash = HashFunctions.normal_hash((int)input);
		}
		else if (hash_type == HashType.xxh) {
			hash = HashFunctions.xxhash(input);
		}
		else {
			System.exit(1);
		}
		return hash;
	}
	
	public abstract long get_num_occupied_slots(boolean include_all_internal_filters);

	
	public double get_utilization() {
		return 0;
	}
	
	public double measure_num_bits_per_entry() {
		return 0;
	}
	
	 static void print_int_in_binary(int num, int length) {
		String str = "";
		for (int i = 0; i < length; i++) {
			int mask = (int)Math.pow(2, i);
			int masked = num & mask;
			str += masked > 0 ? "1" : "0";
		}
		System.out.println(str);
	}
	
	 static void print_long_in_binary(long num, int length) {
		String str = "";
		for (int i = 0; i < length; i++) {
			long mask = (long)Math.pow(2, i);
			long masked = num & mask;
			str += masked > 0 ? "1" : "0";
		}
		System.out.println(str);
	}
	
	String get_fingerprint_str(long fp, int length) {
		String str = "";
		for (int i = 0; i < length; i++) {
			str += Bitmap.get_fingerprint_bit(i, fp) ? "1" : "0";
		}
		return str;
	}
	
	public void pretty_print() {

	}

}
