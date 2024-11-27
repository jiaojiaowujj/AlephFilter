/*
 * Copyright 2024 Niv Dayan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

package filters;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import bitmap_implementations.Bitmap;
import bitmap_implementations.QuickBitVectorWrapper;

public class QuotientFilter extends Filter implements Cloneable {

	int bitPerEntry;
	int fingerprintLength; 
	int power_of_two_size; 
	int num_extension_slots;
	int num_physical_entries;
	Bitmap filter;
	
	// These three fields are used to prevent throwing exceptions when the buffer space of the filter is exceeded 
	long last_empty_slot;
	long last_cluster_start;
	public long backward_steps;
	
	
	
	boolean expand_autonomously; //控制自动扩展
	boolean is_full; //表示 QuotientFilter 是否已满
	
	// statistics, computed in the compute_statistics method. method should be called before these are used
	long num_runs; 
	long num_clusters;
	public double avg_run_length;
	public double avg_cluster_length;
	
	int original_fingerprint_size; 
	
	@Override
	public Object clone() {
		QuotientFilter f = null;
		f = (QuotientFilter) super.clone();
		f.filter = (Bitmap) filter.clone();
		return f;
	}
	
	public QuotientFilter(int power_of_two, int bits_per_entry) {
		//输入两个参数 
		//power_of_two: 决定过滤器的基本大小，定义为2^power_of_two
		//bits_per_entry: 每个条目分配的位数
		
		power_of_two_size = power_of_two; //存储过滤器大小的指数部分
		bitPerEntry = bits_per_entry; //每个条目分配的位数,包含指纹+3个字段比特is_occupied, is_continuation, is_shifted
		fingerprintLength = bits_per_entry - 3; //指纹长度
		long init_size = 1L << power_of_two; //使用左移运算符计算过滤器的初始大小  2^power_of_two
		
		num_extension_slots = power_of_two * 2; //扩展槽的数量
		
		filter = make_filter(init_size, bits_per_entry); // 调用 make_filter 方法创建过滤器
		
		fullness_threshold = 0.8; // 设置为 80%，表示过滤器在存储容量达到 80% 时被认为“满载”
		max_entries_before_full = (int) (init_size * fullness_threshold); //计算过滤器在满载前能存储的最大条目数
		expand_autonomously = true; //是否支持自动扩展
		is_full = false; //初始设置为 false，表示过滤器尚未满载
		
		original_fingerprint_size = fingerprintLength; //保存原始指纹大小
		num_expansions = 0; //扩展次数，初始为 0
		hash_type = HashType.xxh; //设置哈希类型为 HashType.xxh
		
		last_empty_slot = init_size + num_extension_slots - 1; //计算出最后一个空槽的位置，利用初始大小和扩展槽计算
		last_cluster_start = 0; //初始设置为 0，可能用于标记cluster的起点
		backward_steps = 0;
		//measure_num_bits_per_entry();
	}
	
	void setup() {
		
	}

	//nuevo
	void update(long init_size)
	{
		last_empty_slot = init_size + num_extension_slots - 1;
		last_cluster_start = 0;
		backward_steps = 0;
	}
	
	public boolean rejuvenate(long key) {
		return false;
	}
	
	public long get_num_physical_entries() {
		return num_physical_entries;
	}
	
	public long get_max_entries_before_expansion() {
		return max_entries_before_full;
	}
	
	public boolean expand_autonomously() {
		return expand_autonomously;
	} //用于获取实例变量的值
	
	public void set_expand_autonomously(boolean val) {
		expand_autonomously = val;
	} // 设置是否自动扩展
	
	Bitmap make_filter(long init_size, int bits_per_entry) {
		return new QuickBitVectorWrapper(bits_per_entry,  init_size + num_extension_slots);
	}
	//该方法返回类型 Bitmap，作用是生成一个 Bitmap 类型的对象
	// QuickBitVectorWrapper 是一个类，它可能是 Bitmap 的具体实现或子类
	
	public int get_fingerprint_length() {
		return fingerprintLength;
	}
	
	QuotientFilter(int power_of_two, int bits_per_entry, Bitmap bitmap) {
		power_of_two_size = power_of_two;
		bitPerEntry = bits_per_entry; 
		fingerprintLength = bits_per_entry - 3;
		filter = bitmap;
		num_extension_slots = power_of_two * 2;

		//nuevo
		long init_size = 1L << power_of_two;
		last_empty_slot = init_size + num_extension_slots - 1;
		last_cluster_start = 0;
		backward_steps = 0;
	}
	
	public boolean expand() {
		is_full = true; // 已经达到了“满”
		return false; // 表示扩展操作未成功?
	}
	
	// measures the number of bits per entry for the filter 
	public double measure_num_bits_per_entry() {
		return measure_num_bits_per_entry(this, new ArrayList<QuotientFilter>());
	}
	
	// measures the number of bits per entry for the filter 
	// it takes an array of filters as a parameter since some filter implementations here consist of multiple filter objects
	protected static double measure_num_bits_per_entry(QuotientFilter current, ArrayList<QuotientFilter> other_filters) {
		//System.out.println("--------------------------");
		//current.print_filter_summary();
		//System.out.println();
		//double num_entries = current.get_num_occupied_slots(false);
		double total_count = current.get_num_logical_entries();
		for (QuotientFilter q : other_filters) {
			//q.print_filter_summary();
			//System.out.println();
			//long q_num_entries = q.get_num_occupied_slots(false);
			//num_entries += q_num_entries;
			//total_count += q.num_physical_entries;
		}
		//System.out.println("entry count: " + total_count + "  " + num_entries); 
		double init_size = 1L << current.power_of_two_size;
		double num_bits = current.bitPerEntry * init_size + current.num_extension_slots * current.bitPerEntry;
		for (QuotientFilter q : other_filters) {
			init_size = 1L << q.power_of_two_size;
			num_bits += q.bitPerEntry * init_size + q.num_extension_slots * q.bitPerEntry;
		}
		//System.out.println("total entries: \t\t" + num_entries);
		//System.out.println("total bits: \t\t" + num_bits);
		
		//System.out.println("entries:  " + total_count + "  bits:  " + num_bits); 

		
		double bits_per_entry = num_bits / total_count;
		//System.out.println("total bits/entry: \t" + bits_per_entry);
		//System.out.println();
 		return bits_per_entry;
	}
	
	// scans the quotient filter and returns the number of non-empty slots
	public long get_num_occupied_slots(boolean include_all_internal_filters) {
		//long bits = filter.size();
		long slots = get_physcial_num_slots();
		long num_entries = 0;
		for (long i = 0; i < slots; i++) {
			if (is_occupied(i) || is_continuation(i) || is_shifted(i)) {
				num_entries++;
			}
		}
		return num_entries;
	}
	
	// returns the fraction of occupied slots in the filter
	public double get_utilization() {
		long num_logical_slots = get_logical_num_slots_plus_extensions();
		// num_entries = get_num_occupied_slots(false);
		double util = get_num_physical_entries() / (double) num_logical_slots;
		return util;
	}
	
	public long get_physcial_num_slots() {
		long bits = filter.size();
		return bits / bitPerEntry;
	}
	
	// returns the number of physical slots in the filter (including the extention/buffer slots at the end)
	// 返回过滤器中槽的数量（包括末尾的扩展/缓冲槽）
	public long get_logical_num_slots_plus_extensions() {
		return (1L << power_of_two_size) + num_extension_slots; //2^power_of_two_size + num_extension_slots
	}
	
	// returns the number of slots in the filter without the extension/buffer slots
	// 返回过滤器中不包含扩展/缓冲槽的槽数
	public long get_logical_num_slots() {
		return 1L << power_of_two_size; //2^power_of_two_size
	}
	//num_extension_slots 扩展槽的作用？
	
	// sets the metadata flag bits for a given slot index
	void modify_slot(boolean is_occupied, boolean is_continuation, boolean is_shifted, 
			long index) {
		set_occupied(index, is_occupied);
		set_continuation(index, is_continuation);
		set_shifted(index, is_shifted);
	}
	
	// sets the fingerprint for a given slot index
	void set_fingerprint(long index, long fingerprint) {
		filter.setFromTo(index * bitPerEntry + 3, (long)index * bitPerEntry + 3 + fingerprintLength, fingerprint);
	}
	
	// print a nice representation of the filter that can be understood. 
	// if vertical is on, each line will represent a slot
	public String get_pretty_str(boolean vertical) {
		StringBuffer sbr = new StringBuffer();
		
		long logic_slots = get_logical_num_slots();
		long all_slots = get_logical_num_slots_plus_extensions();
		
		for (long i = 0; i < filter.size(); i++) {
		//for (long i = 0; i < 100; i++) {

			long remainder = i % bitPerEntry;
			if (remainder == 0) {
				long slot = i / bitPerEntry;
				long slot_num = i/bitPerEntry;
				sbr.append(" ");
				if (vertical) {
					if (slot_num == logic_slots || slot_num == all_slots) {
						sbr.append("\n ---------");
					}
					sbr.append("\n" + slot_num + " ");
				}
			}
			if (remainder == 3) {
				sbr.append(" ");
			}
			sbr.append(filter.get(i) ? "1" : "0");
		}
		sbr.append("\n");
		return sbr.toString();
	}
	
	// print a nice representation of the filter that can be humanly read. 
	public void pretty_print() {	
		System.out.print(get_pretty_str(true));
	}

	// return a fingerprint in a given slot index
	long get_fingerprint(long index) {
		return filter.getFromTo(index * bitPerEntry + 3, index * bitPerEntry + 3 + fingerprintLength);
	}
	
	// return an entire slot representation, including metadata flags and fingerprint
	long get_slot(long index) {
		return filter.getFromTo(index * bitPerEntry, (index + 1) * bitPerEntry);
	}
	
	// compare a fingerprint input to the fingerprint in some slot index
	protected boolean compare(long index, long fingerprint) {
		return get_fingerprint(index) == fingerprint;
	}
	
	// modify the flags and fingerprint of a given slot
	void modify_slot(boolean is_occupied, boolean is_continuation, boolean is_shifted, 
			long index, long fingerprint) {
		modify_slot(is_occupied, is_continuation, is_shifted, index);
		set_fingerprint(index, fingerprint);
	}
	
	// summarize some statistical measures about the filter
	public void print_filter_summary() {	
		long num_entries = get_num_occupied_slots(false);
		long slots = (1L << power_of_two_size) + num_extension_slots;
		long num_bits = slots * bitPerEntry;
		System.out.println("slots:\t" + slots);
		System.out.println("entries:\t" + num_entries);
		System.out.println("num_physical_entries:\t" + num_physical_entries);
		System.out.println("num_logical_entries:\t" + num_logical_entries);
		System.out.println("bits\t:" + num_bits);
		System.out.println("bits/entry\t:" + num_bits / (double)num_entries);
		System.out.println("FP length:\t" + fingerprintLength);
		compute_statistics();	
		//System.out.println("num runs: \t\t" + num_runs);
		//System.out.println("avg run length: \t" + avg_run_length);
		//System.out.println("num clusters: \t\t" + num_clusters);
		//System.out.println("avg cluster length: \t" + avg_cluster_length);
	}
	
	boolean is_occupied(long index) { //检查给定索引 index (slot) 是否被占用，返回is_occupied对应的结果，true或false
		return filter.get(index * bitPerEntry);
	}
	
	boolean is_continuation(long index) { //检查给定索引 index 是否在一个run内
		return filter.get(index * bitPerEntry + 1);
	}
	
	boolean is_shifted(long index) {
		return filter.get(index * bitPerEntry + 2); //检查给定索引 index 是否在一个cluster内
	}
	
	void set_occupied(long index, boolean val) {
		filter.set(index * bitPerEntry, val);//调用QuickBitVectorWrapper.java中set(),把filter中index对应的slot
	}
	
	void set_continuation(long index, boolean val) {
		filter.set(index * bitPerEntry + 1, val);
	}
	
	void set_shifted(long index, boolean val) {
		filter.set(index * bitPerEntry + 2, val);
	}
	
	boolean is_slot_empty(long index) {//判断一个slot是否为空，如果该slot的三个比特均为0，则认为该slot为空，返回true,否则返回false（即三个比特存在任意一位为0）
		return !is_occupied(index) && !is_continuation(index) && !is_shifted(index);
	}
	
	// scan the cluster leftwards until finding the start of the cluster and returning its slot index
	// used by deletes
	long find_cluster_start(long index) {
		long current_index = index;
		while (is_shifted(current_index)) {
			current_index--;
		}
		return current_index;
	}

	// given a canonical slot A, finds the actual index B of where the run belonging to slot A now resides
	// since the run might have been shifted to the right due to collisions
	long find_run_start(long index) {// index 是slot的标号，从0开始
		long current_index = index; 
		int runs_to_skip_counter = 1;
		while (is_shifted(current_index)) {
			if (is_occupied(current_index)) {
				runs_to_skip_counter++;
			}
			current_index--;
		}
		last_cluster_start = current_index - 1;
		while (true) {
			if (!is_continuation(current_index)) {
				runs_to_skip_counter--;
				if (runs_to_skip_counter == 0) {
					return current_index;
				}
			}
			current_index++;
		}
	}
	
	// given the start of a run, scan the run and return the index of the first matching fingerprint
	long find_first_fingerprint_in_run(long index, long fingerprint) {
		assert(!is_continuation(index));
		do {
			if (compare(index, fingerprint)) {
				//System.out.println("found matching FP at index " + index);
				return index; 
			}
			index++;
		} while (index < get_logical_num_slots_plus_extensions() && is_continuation(index));
		return -1; 
	}
	
	// delete the last matching fingerprint in the run
	long decide_which_fingerprint_to_delete(long index, long fingerprint) {
		long matching_fingerprint_index = -1;
		do {
			if (compare(index, fingerprint)) {
				//System.out.println("found matching FP at index " + index);
				matching_fingerprint_index = index;
			}
			index++;
		} while (index < get_logical_num_slots_plus_extensions() && is_continuation(index));
		return matching_fingerprint_index; 
	}
	
	// given the start of a run, find the last slot index that still belongs to this run
	long find_run_end(long index) {
		while(index < get_logical_num_slots_plus_extensions() - 1 && is_continuation(index+1)) {
			index++;
		} 
		return index; 
	}
	
	// given a canonical index slot and a fingerprint, find the relevant run and check if there is a matching fingerprint within it
	boolean search(long fingerprint, long index) {
		boolean does_run_exist = is_occupied(index);
		if (!does_run_exist) {
			return false;
		}
		long run_start_index = find_run_start(index);
		long found_index = find_first_fingerprint_in_run(run_start_index, fingerprint);
		return found_index > -1;
	}
	
	// Given a canonical slot index, find the corresponding run and return all fingerprints in the run.
	// This method is only used for testing purposes.
	Set<Long> get_all_fingerprints(long bucket_index) {
		boolean does_run_exist = is_occupied(bucket_index);
		HashSet<Long> set = new HashSet<Long>();
		if (!does_run_exist) {
			return set;
		}
		long run_index = find_run_start(bucket_index);
		do {
			set.add(get_fingerprint(run_index));
			run_index++;
		} while (is_continuation(run_index));		
		return set;
	}
	
	// Swaps the fingerprint in a given slot with a new one. Return the pre-existing fingerprint
	long swap_fingerprints(long index, long new_fingerprint) {
		long existing = get_fingerprint(index);
		set_fingerprint(index, new_fingerprint);
		return existing;
	}
	
	// finds the first empty slot after the given slot index
	long find_first_empty_slot(long index) {
		while (!is_slot_empty(index)) {
			index++;
		}
		return index;
	}
	
	// moves backwards to find the first empty slot
	// used as a part of the mechanism to prevent exceptions when exceeding the quotient filter's bounds 
	long find_backward_empty_slot(long index) {
		while (index >= 0 && !is_slot_empty(index)) {
			backward_steps++;
			index--;
		}
		return index;
	}
	
	// return the first slot to the right where the current run starting at the index parameter ends
	long find_new_run_location(long index) {
		if (!is_slot_empty(index)) {
			index++;
		}
		while (is_continuation(index)) {
			index++;
		}
		return index;
	}
	
	boolean insert_new_run(long canonical_slot, long long_fp) {//把指纹插入到
		long first_empty_slot = find_first_empty_slot(canonical_slot); // finds the first empty slot to the right of the canonical slot that is empty
		long preexisting_run_start_index = find_run_start(canonical_slot); // scans the cluster leftwards and then to the right until reaching our run's would be location
		long start_of_this_new_run = find_new_run_location(preexisting_run_start_index); // If there is already a run at the would-be location, find its end and insert the new run after it
		boolean slot_initially_empty = is_slot_empty(start_of_this_new_run); 
		
		// modify some metadata flags to mark the new run
		set_occupied(canonical_slot, true);
		if (first_empty_slot != canonical_slot) {
			set_shifted(start_of_this_new_run, true);
		}
		set_continuation(start_of_this_new_run, false);
		
		// if the slot was initially empty, we can just terminate, as there is nothing to push to the right
		if (slot_initially_empty) {
			set_fingerprint(start_of_this_new_run, long_fp);
			if (start_of_this_new_run == last_empty_slot) {  
				last_empty_slot = find_backward_empty_slot(last_cluster_start);
			}
			num_physical_entries++;
			return true; 
		}
		
		// push all entries one slot to the right
		// if we inserted this run in the middle of a cluster
		long current_index = start_of_this_new_run;
		boolean is_this_slot_empty;
		boolean temp_continuation = false;
		do {
			if (current_index >= get_logical_num_slots_plus_extensions()) {
				return false;
			}
			
			is_this_slot_empty = is_slot_empty(current_index);
			long_fp = swap_fingerprints(current_index, long_fp);

			if (current_index > start_of_this_new_run) {
				set_shifted(current_index, true);
			}
			
			if (current_index > start_of_this_new_run) {
				boolean current_continuation = is_continuation(current_index);
				set_continuation(current_index, temp_continuation);
				temp_continuation = current_continuation;
			}
			current_index++;
			if (current_index == last_empty_slot) {  // TODO get this out of the while loop
				last_empty_slot = find_backward_empty_slot(last_cluster_start);
			}
		} while (!is_this_slot_empty);
		num_physical_entries++;
		return true; 
	}
	
	boolean insert(long long_fp, long index, boolean insert_only_if_no_match) {
		if (index > last_empty_slot) {//判断插入的 index 是否超出了filter的最后一个slot的位置；如果超出，则插入失败。
			return false;
		}
		boolean does_run_exist = is_occupied(index);//取出 index 对应的 slot 中 is_occupied 是 true 还是 false
		if (!does_run_exist) { //如果is_occupied=false（即该slot曾经没有作为候选slot，也就是说还没有开启一个新的run），那么就把指纹放在该slot
			boolean val = insert_new_run(index, long_fp);
			return val;
		}
		
		long run_start_index = find_run_start(index);
		//如果 is_occupied = true ，说明之前已经有数据也是属于这个run，但是该run真实的开始并不在候选的slot里，因此需要找到run的真实开始位置
		//该算法就是找到该指纹所述run的真实开始位置
		if (does_run_exist && insert_only_if_no_match) {
			long found_index = find_first_fingerprint_in_run(run_start_index, long_fp);
			if (found_index > -1) {
				return false; 
			}
		} 
		return insert_fingerprint_and_push_all_else(long_fp, run_start_index);
	}
	
	// insert an fingerprint as the first fingerprint of the new run and push all other entries in the cluster to the right.
	boolean insert_fingerprint_and_push_all_else(long long_fp, long run_start_index) {
		long current_index = run_start_index;
		boolean is_this_slot_empty;
		boolean finished_first_run = false;
		boolean temp_continuation = false;
				
		do {
			if (current_index >= get_logical_num_slots_plus_extensions()) {	 
				return false;
			}
			is_this_slot_empty = is_slot_empty(current_index);
			if (current_index > run_start_index) {			
				set_shifted(current_index, true);
			}
			if (current_index > run_start_index && !finished_first_run && !is_continuation(current_index)) {	
				finished_first_run = true;
				set_continuation(current_index, true);
				long_fp = swap_fingerprints(current_index, long_fp);
			}
			else if (finished_first_run) {			
				boolean current_continuation = is_continuation(current_index);
				set_continuation(current_index, temp_continuation);
				temp_continuation = current_continuation;
				long_fp = swap_fingerprints(current_index, long_fp);
			}
			if (current_index == last_empty_slot) {  
				last_empty_slot = find_backward_empty_slot(last_cluster_start);
			}
			current_index++;
		} while (!is_this_slot_empty);
		num_physical_entries++;
		return true; 
	}
	
	boolean delete(long fingerprint, long canonical_slot, long run_start_index, long matching_fingerprint_index) {
		long run_end = find_run_end(matching_fingerprint_index);
		
		// the run has only one entry, we need to disable its is_occupied flag
		// we just remember we need to do this here, and we do it later to not interfere with counts
		boolean turn_off_occupied = run_start_index == run_end;
		
		// First thing to do is move everything else in the run back by one slot
		for (long i = matching_fingerprint_index; i < run_end; i++) {
			long f = get_fingerprint(i + 1);
			set_fingerprint(i, f);
		}

		// for each slot, we want to know by how much the entry there is shifted
		// we can do this by counting the number of continuation flags set to true 
		// and the number of occupied flags set to false from the start of the cluster to the given cell
		// and then subtracting: num_shifted_count - num_non_occupied = number of slots by which an entry is shifted 
		long cluster_start = find_cluster_start(canonical_slot);
		long num_shifted_count = 0;
		long num_non_occupied = 0;
		for (long i = cluster_start; i <= run_end; i++) {
			if (is_continuation(i)) {
				num_shifted_count++;
			}
			if (!is_occupied(i)) {
				num_non_occupied++;
			}
		}
		
		set_fingerprint(run_end, 0); 
		set_shifted(run_end, false);
		set_continuation(run_end, false);
		
		// we now have a nested loop. The outer do-while iterates over the remaining runs in the cluster. 
		// the inner for loop iterates over cells of particular runs, pushing entries one slot back. 
		do {
			// we first check if the next run actually exists and if it is shifted.
			// only if both conditions hold, we need to shift it back one slot.
			//boolean does_next_run_exist = !is_slot_empty(run_end + 1);
			//boolean is_next_run_shifted = is_shifted(run_end + 1);
			//if (!does_next_run_exist || !is_next_run_shifted) {
			if (run_end >= get_logical_num_slots_plus_extensions()-1 ||
				 is_slot_empty(run_end + 1) || !is_shifted(run_end + 1)) {
				if (turn_off_occupied) {
					// if we eliminated a run and now need to turn the is_occupied flag off, we do it at the end to not interfere in our counts 
					set_occupied(canonical_slot, false);
					
				}
				if (run_end > last_empty_slot) {         
					last_empty_slot = run_end;
				}
				return true;
			}
			
			// we now find the start and end of the next run
			long next_run_start = run_end + 1;
			run_end = find_run_end(next_run_start);
			
			// before we start processing the next run, we check whether the previous run we shifted is now back to its canonical slot
			// The condition num_shifted_count - num_non_occupied == 1 ensures that the run was shifted by only 1 slot, meaning it is now back in its proper place
			if ( is_occupied(next_run_start - 1) && num_shifted_count - num_non_occupied == 1 ) {
				set_shifted(next_run_start - 1, false); 
			}
			else  {
				set_shifted(next_run_start - 1, true);
			}

			for (long i = next_run_start; i <= run_end; i++) {
				long f = get_fingerprint(i);
				set_fingerprint(i - 1, f);
				if (is_continuation(i)) {
					set_continuation(i-1, true);
				}
				if (!is_occupied(i)) {
					num_non_occupied++;
				}
			}
			num_shifted_count += run_end - next_run_start;
			set_fingerprint(run_end, 0);
			set_shifted(run_end, false);
			set_continuation(run_end, false);
		} while (true);
	}
	
	long delete(long fingerprint, long canonical_slot) {
		if (canonical_slot >= get_logical_num_slots()) {
			return -1;
		}
		// if the run doesn't exist, the key can't have possibly been inserted
		boolean does_run_exist = is_occupied(canonical_slot);
		if (!does_run_exist) {
			return -1;
		}
		long run_start_index = find_run_start(canonical_slot);
		
		long matching_fingerprint_index = decide_which_fingerprint_to_delete(run_start_index, fingerprint);
		
		if (matching_fingerprint_index == -1) {
			// we didn't find a matching fingerprint
			return -1;
		}
		
		long removed_fp = get_fingerprint(matching_fingerprint_index);


		boolean success = delete(fingerprint, canonical_slot, run_start_index, matching_fingerprint_index);
		
		return success ? removed_fp : -1;
		
	}


	
	long get_slot_index(long large_hash) {
		//从哈希值 (large_hash) 中提取对应的槽索引（slot_index）,即提取 large_hash 的最低 power_of_two_size 位，用于确定哈希表中的槽索引，例如：0100110001010 中1010（假设power_of_two_size=4）
		long slot_index_mask = (1L << power_of_two_size) - 1;
		long slot_index = large_hash & slot_index_mask;
		//System.out.format("\n**get_slot_index(): [total_hash:index_hash:int_index] --> [%016x:%016x:%016x]\n", large_hash, (int)large_hash, slot_index);
		return slot_index;
	}
	
	long gen_fingerprint(long large_hash) {
		//从哈希值 (large_hash) 中提取对应的指纹（fingerprint）,即提取 large_hash 的 fingerprintLength 位（除去slot_index的最低fingerprintLength的比特位）
		//例如：0100110001010 中11000（假设fingerprintLength=5）
		long fingerprint_mask = (1L << fingerprintLength) - 1L;
		fingerprint_mask = fingerprint_mask << power_of_two_size;
		long fingerprint = (large_hash & fingerprint_mask) >> power_of_two_size;
		//System.out.format("\n**gen_fingerprint(): [total_hash:fingerprint_hash:int_fingerprint] --> [%016x:%016x:%016x]\n", large_hash, ((int)(large_hash>>32)), fingerprint);
		return fingerprint;
	}
	
	void print_key(int input) {
		long large_hash = HashFunctions.normal_hash(input);
		long slot_index = get_slot_index(large_hash);
		long fingerprint = gen_fingerprint(large_hash);
		
		System.out.println("num   :  " + input);
		System.out.print("hash  :  ");
		print_long_in_binary(large_hash, fingerprintLength + power_of_two_size);
		//print_int_in_binary(slot_index_mask, 31);
		System.out.print("bucket:  ");
		print_long_in_binary(slot_index, power_of_two_size);
		System.out.print("FP    :  ");
		//print_int_in_binary(fingerprint_mask, 31);
		print_long_in_binary(fingerprint, fingerprintLength);
		System.out.println();

	}

	public void set_expansion_threshold(double thresh) {
		fullness_threshold = thresh;
		max_entries_before_full = (long)(Math.pow(2, power_of_two_size) * fullness_threshold);
	} //在哪里调用？
	
	protected boolean _insert(long large_hash, boolean insert_only_if_no_match) { //和insert方法的区别？
		if (is_full) {
			return false; //// 如果过滤器已经满了，则返回 false，停止插入！
		}
		long slot_index = get_slot_index(large_hash);  // 根据 large_hash 获取插入的槽位索引
		long fingerprint = gen_fingerprint(large_hash); // 根据 large_hash 生成指纹（哈希值）
		
		/*print_long_in_binary(large_hash, 64);
		print_long_in_binary(slot_index, 32);
		print_long_in_binary((int)fingerprint, 64);
		System.out.println(slot_index + "  " + fingerprint );
		System.out.println(); */
		
		boolean success = insert(fingerprint, slot_index, false); // 执行插入操作，尝试将指纹插入到槽位中
		/*if (!success) {
			System.out.println("insertion failure");
			System.out.println(input + "\t" + slot_index + "\t" + get_fingerprint_str(fingerprint, fingerprintLength));
			pretty_print();
			System.exit(1);
		}*/
		// 如果设置了自动扩展，并且当前条目数大于扩展前的最大值，则执行扩展操作。num_physical_entries？？max_entries_before_full？？
		if (expand_autonomously && num_physical_entries >= max_entries_before_full) {
			boolean expanded = expand();//设置is_full = true，返回false
			if (expanded) {
				num_expansions++;
			}
		}
		return success; 
	}

	protected long _delete(long large_hash) {
		long slot_index = get_slot_index(large_hash);
		long fp_long = gen_fingerprint(large_hash);
		long removed_fp = delete(fp_long, slot_index);
		if (removed_fp > -1) {
			num_physical_entries--;
		}
		return removed_fp; 
	}

	protected boolean _search(long large_hash) {
		long slot_index = get_slot_index(large_hash);
		long fingerprint = gen_fingerprint(large_hash);
		return search(fingerprint, slot_index);
	}


	
	public boolean get_bit_at_offset(int offset) {
		return filter.get(offset);
	}

	public Map<Integer,Integer> compute_statistics() {
		num_runs = 0;
		num_clusters = 0; 
		Map<Integer,Integer> histogram = new TreeMap<Integer,Integer>();
		
		double sum_run_lengths = 0;
		double sum_cluster_lengths = 0; 
		
		int current_run_length = 0;
		int current_cluster_length = 0;
		
		long num_slots = get_logical_num_slots_plus_extensions();		
		for (long i = 0; i < num_slots; i++) {
			
			boolean occupied = is_occupied(i);
			boolean continuation = is_continuation(i); 
			boolean shifted = is_shifted(i);
			
			if 	( !occupied && !continuation && !shifted ) { // empty slot
				sum_cluster_lengths += current_cluster_length;
				int new_hist_val = 1;
				if (histogram.containsKey(current_cluster_length)) {
					new_hist_val = histogram.get(current_cluster_length) + 1;
				}
				histogram.put(current_cluster_length, new_hist_val);
				
				current_cluster_length = 0; 
				sum_run_lengths += current_run_length;
				current_run_length = 0;
			}
			else if ( !occupied && !continuation && shifted ) { // start of new run
				num_runs++;
				sum_run_lengths += current_run_length;
				current_run_length = 1;
				current_cluster_length++;
			}
			else if ( !occupied && continuation && !shifted ) {
				// not used
			}
			else if ( !occupied && continuation && shifted ) { // continuation of run
				current_cluster_length++;
				current_run_length++;
			}
			else if ( occupied && !continuation && !shifted ) { // start of new cluster & run
				num_runs++;
				num_clusters++;
				sum_cluster_lengths += current_cluster_length;
				int new_hist_val = 1;
				if (histogram.containsKey(current_cluster_length)) {
					new_hist_val = histogram.get(current_cluster_length) + 1;
				}
				histogram.put(current_cluster_length, new_hist_val);				sum_run_lengths += current_run_length;
				current_cluster_length = 1; 
				current_run_length = 1;
			}
			else if (occupied && !continuation && shifted ) { // start of new run
				num_runs++;
				sum_run_lengths += current_run_length;
				current_run_length = 1; 
				current_cluster_length++;
			}
			else if (occupied && continuation && !shifted ) {
				// not used
			}
			else if (occupied && continuation && shifted ) { // continuation of run
				current_cluster_length++;
				current_run_length++;
			}
		}
		avg_run_length = sum_run_lengths / num_runs;
		avg_cluster_length = sum_cluster_lengths / num_clusters;
		return histogram;
	}


	void ar_sum1(ArrayList<Integer> ar, int index)
	{
		int s = ar.size();
		if (s <= index)
		{
			for (int i = s; i<index+1; i++)
			{
				ar.add(0);
			}
		}
		ar.set(index, ar.get(index)+1);
	}

	public ArrayList<Integer> measure_cluster_length()
	{
		ArrayList<Integer> ar = new ArrayList<Integer>();
		
		num_runs = 0;
		num_clusters = 0; 
	
		int current_run_length = 0;
		int current_cluster_length = 0;

		int cnt = 0;
		
		for (int i = 0; i < get_logical_num_slots_plus_extensions(); i++) {
			
			boolean occupied = is_occupied(i);
			boolean continuation = is_continuation(i); 
			boolean shifted = is_shifted(i);
			
			if 	(!occupied && !continuation && !shifted ) { // empty slot
				if(current_cluster_length != 0) ar_sum1(ar, current_cluster_length-1);
				current_cluster_length = 0;
				current_run_length = 0;
			}
			else if (!occupied && !continuation && shifted ) { // start of new run
				num_runs++;
				current_run_length = 1;
				current_cluster_length++;
			}
			else if (!occupied && continuation && shifted ) { // continuation of run
				current_cluster_length++;
				current_run_length++;
			}
			else if (occupied && !continuation && !shifted ) { // start of new cluster & run
				if(current_cluster_length != 0) ar_sum1(ar, current_cluster_length-1);
				num_runs++;
				num_clusters++;
				//if(current_cluster_length == 0) cnt++;
				current_cluster_length = 1; 
				current_run_length = 1;
			}
			else if (occupied && !continuation && shifted ) { // start of new run
				num_runs++;
				current_run_length = 1; 
				current_cluster_length++;
			}
			else if (occupied && continuation && shifted ) { // continuation of run
				current_cluster_length++;
				current_run_length++;
			}
		}
		if(current_cluster_length != 0) ar_sum1(ar, current_cluster_length-1);
		//System.out.println("CNT = " + cnt);
		return ar;
	}


	
}

