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

import java.util.Map.Entry;

import bitmap_implementations.Bitmap;

import java.util.TreeMap;

public class BasicInfiniFilter extends QuotientFilter implements Cloneable {
	//BasicInfiniFilter 的父类是QuotientFilter

	protected long empty_fingerprint;
	int num_void_entries = 0;
	FingerprintGrowthStrategy.FalsePositiveRateExpansion fprStyle = FingerprintGrowthStrategy.FalsePositiveRateExpansion.UNIFORM;
	//定义了扩展后假阳性率变化的风格，此处为uniform, 即new_filter_FPR = original_FPR
	
	int num_distinct_void_entries = 0;
	int num_expansions_estimate = -1;
	
	public void set_fpr_style(FingerprintGrowthStrategy.FalsePositiveRateExpansion val) {
		fprStyle = val;
	}
	
	BasicInfiniFilter(int power_of_two, int bits_per_entry) {
		super(power_of_two, bits_per_entry); // 调用了父类的构造函数 QuotientFilter，传递了两个参数 power_of_two 和 bits_per_entry; super是java的一个关键词，用于引用当前类的直接父类的成员（包括方法和构造函数）
		max_entries_before_full = (long)(Math.pow(2, power_of_two_size) * fullness_threshold); //计算过滤器的理论最大容量
		set_empty_fingerprint(fingerprintLength); //初始化过滤器中表示“空槽位”的指纹值?
	}
	
	@Override
	public Object clone() {
		BasicInfiniFilter f = null;
		f = (BasicInfiniFilter) super.clone();
		f.fprStyle = fprStyle;
		return f;
	}
	
	void set_empty_fingerprint(long fp_length) {
		empty_fingerprint = (1L << fp_length) - 2L;
	}
	//作用是为过滤器设置“空槽位”的指纹值
	//参数 fp_length 指纹长度
	//计算并设置一个特殊的指纹值，用来标记过滤器中的“空槽”, 生成的指纹值接近但小于2^fp_length
	//如果 fp_length = 4：(1L << 4) - 2L = 16 - 2 = 14（二进制为 1110）
	
	public int get_num_void_entries() {
		return num_void_entries;
	}
	
	protected boolean compare(long index, long fingerprint) {
		long generation = parse_unary(index);
		return compare(index, fingerprint, generation);
	}
	
	protected boolean compare(long index, long fingerprint, long generation) {
		long first_fp_bit = index * bitPerEntry + 3;
		long last_fp_bit = index * bitPerEntry + 3 + fingerprintLength - (generation + 1);
		long actual_fp_length = last_fp_bit - first_fp_bit;
		long mask = (1L << actual_fp_length) - 1L;
		long existing_fingerprint = filter.getFromTo(first_fp_bit, last_fp_bit);
		long adjusted_saught_fp = fingerprint & mask;
		return existing_fingerprint == adjusted_saught_fp;
	}
	
	protected boolean compare(long index, long search_fingerprint, long generation, long slot_fingerprint) {
		long mask = (1 << (fingerprintLength - generation - 1)) - 1;
		long adjusted_saught_fp = search_fingerprint & mask;
		long adjusted_existing_fp = slot_fingerprint & mask;
		return adjusted_existing_fp == adjusted_saught_fp;
	}
		
	// this is the newer version of parsing the unary encoding. 
	// it is done using just binary operations and no loop. 
	// however, this optimization didn't yield much performance benefit 
	long parse_unary(long slot_index) {
		long f = get_fingerprint(slot_index);
		//.out.println();
		//System.out.println(get_pretty_str(slot_index));
		//print_long_in_binary(f, 32);
		long inverted_fp = ~f;
		//print_long_in_binary(inverted_fp, 32);
		long mask = (1L << fingerprintLength) - 1;
		//print_long_in_binary(mask, 32);
		long masked = mask & inverted_fp;
		//print_long_in_binary(masked, 32);
		long highest = Long.highestOneBit(masked);
		//print_long_in_binary(highest, 32);
		long leading_zeros = Long.numberOfTrailingZeros(highest);
		//System.out.println( leading_zeros );
		long age = fingerprintLength - leading_zeros - 1;
		//System.out.println( age );
		return age;
	}
	
	long parse_unary_from_fingerprint(long fingerprint) {
		//.out.println();
		//System.out.println(get_pretty_str(slot_index));
		//print_long_in_binary(f, 32);
		long inverted_fp = ~fingerprint;
		//print_long_in_binary(inverted_fp, 32);
		long mask = (1L << fingerprintLength) - 1;
		//print_long_in_binary(mask, 32);
		long masked = mask & inverted_fp;
		//print_long_in_binary(masked, 32);
		long highest = Long.highestOneBit(masked);
		//print_long_in_binary(highest, 32);
		long leading_zeros = Long.numberOfTrailingZeros(highest);
		//System.out.println( leading_zeros );
		long age = fingerprintLength - leading_zeros - 1;
		//System.out.println( age );
		return age;
	}
	
	// TODO if we rejuvenate a void entry, we should subtract from num_void_entries 
	// as if this count reaches zero, we can have shorter chains
	public boolean rejuvenate(long key) {
		long large_hash = get_hash(key);
		long fingerprint = gen_fingerprint(large_hash);
		long ideal_index = get_slot_index(large_hash);
		
		boolean does_run_exist = is_occupied(ideal_index);
		if (!does_run_exist) {
			return false;
		}
		
		long run_start_index = find_run_start(ideal_index);
		long smallest_index = find_largest_matching_fingerprint_in_run(run_start_index, fingerprint);
		if (smallest_index == -1) {
			return false;
		}
		swap_fingerprints(smallest_index, fingerprint);
		return true; 
	}

	
	long decide_which_fingerprint_to_delete(long index, long fingerprint) {
		return find_largest_matching_fingerprint_in_run(index, fingerprint);
	}
	
	// returns the index of the entry if found, -1 otherwise
	long find_largest_matching_fingerprint_in_run(long index, long fingerprint) {
		long matching_fingerprint_index = -1;
		long lowest_age = Integer.MAX_VALUE;
		do {
			long slot_fp = get_fingerprint(index);
			long age = parse_unary_from_fingerprint(slot_fp);
			//System.out.println("age " + age);
			if (compare(index, fingerprint, age, slot_fp)) {
				if (age == 0) {
					return index;
				}
				if (age < lowest_age) {
					lowest_age = age;
					matching_fingerprint_index = index;
				}
			}
			index++;
		} while (is_continuation(index));
		return matching_fingerprint_index; 
	}
	
	long gen_fingerprint(long large_hash) {
		long fingerprint_mask = (1L << fingerprintLength) - 1L;
		fingerprint_mask = fingerprint_mask << power_of_two_size;
		long fingerprint = (large_hash & fingerprint_mask) >> power_of_two_size;
		long unary_mask = ~(1L << (fingerprintLength - 1L));
		long updated_fingerprint = fingerprint & unary_mask;
		/*System.out.println(); 
		print_long_in_binary(unary_mask, fingerprintLength);
		print_long_in_binary( fingerprint, fingerprintLength);
		print_long_in_binary( updated_fingerprint, fingerprintLength);*/
		return updated_fingerprint;
	}
	
	void handle_empty_fingerprint(long bucket_index, QuotientFilter insertee) {//都注释掉了，等于啥也没干
		//System.out.println("called");
		/*long bucket1 = bucket_index;
		long bucket_mask = 1L << power_of_two_size; 		// setting this bit to the proper offset of the slot address field
		long bucket2 = bucket1 | bucket_mask;	// adding the pivot bit to the slot address field
		insertee.insert(empty_fingerprint, bucket1, false);
		insertee.insert(empty_fingerprint, bucket2, false);*/
	}
	
	private static int prep_unary_mask(int prev_FP_size, int new_FP_size) {//产生一个新指纹长度的字符串 1000...0，也就说生成 unary counter,当扩展一次，把第一个比特设为1
		int fingerprint_diff = new_FP_size - prev_FP_size;
		
		int unary_mask = 0;
		for (int i = 0; i < fingerprint_diff + 1; i++) {
			unary_mask <<= 1;
			unary_mask |= 1;
		}
		unary_mask <<= new_FP_size - 1 - fingerprint_diff;
		return unary_mask;
	}
	
	int get_num_void_entries_by_counting() {
		int num = 0;
		for (long i = 0; i < get_physcial_num_slots(); i++) {
			long fp = get_fingerprint(i);
			if (fp == empty_fingerprint) {
				num++;
			}
		}
		return num;
	}

	
	void report_void_entry_creation(long slot) {//输入slot有什么作用？
		num_distinct_void_entries++;
		num_void_entries++;
	}
	
	public boolean expand() {//扩展qr为new_qr，将就的qr元素重新插入到新的new_qr
		if (is_full()) {
			//检查 is_full() 返回true(即 num_void_entries>0)；则if返回false; num_void_entries>0意味着某个旧元素更新后的指纹恰巧等于“空指纹”？
			//检查 is_full() 返回false(即 num_void_entries 等于0)；则不执行if
			return false;
		}
		//此时num_void_entries=0
		
		int new_fingerprint_size = FingerprintGrowthStrategy.get_new_fingerprint_size(original_fingerprint_size, num_expansions, num_expansions_estimate, fprStyle); 
		//计算新的指纹长度,使用 FingerprintGrowthStrategy 来确定扩展后的指纹长度
		//original_fingerprint_size 是 QuotientFilter中定义的成员变量，原始指纹长度，因此 BasicInfiniFilter.java 继承了下来，直接调用. original_fingerprint_size = fingerprintLength=bits_per_entry - 3;
		//QuotientFilter()中定义的num_expansions = 0;
		//本类中定义的成员变量 int num_expansions_estimate = -1;
		//fprStyle=UNIFORM 即 new_filter_FPR = original_FPR = 2^-original_fingerprint_size
		//new_fingerprint_size=Math.ceil( Math.log(1.0 / new_filter_FPR) / Math.log(2) ); 
			//解析：1.0 / new_filter_FPR 将假阳性率转换为一个反比值。如果假阳性率 FPR = 0.01，则 1.0 / FPR = 100
			//对反比值取对数 log (底数默认为e)
			//转化底数为2的对数，例如log_2 100 = 6.64
			//向上取整 log_2 100 = 7
		//因为fprStyle=UNIFORM，假阳性率不变，因此新的指纹长度也不变
		
		//System.out.println("FP size: " + new_fingerprint_size);
		//new_fingerprint_size = Math.max(new_fingerprint_size, fingerprintLength);
		
		// we can't currently remove more than one bit at a time from a fingerprint during expansion
		// This means we'd be losing bits from the mother hash and result in false negatives 
		if (new_fingerprint_size < fingerprintLength) {//确保新的指纹长度不会小于当前长度，以避免数据丢失或产生错误；如果小，也仅设置为减去一个比特
			new_fingerprint_size = fingerprintLength - 1;
		}
	
		
		QuotientFilter new_qf = new QuotientFilter(power_of_two_size + 1, new_fingerprint_size + 3); //构建新的 Quotient Filter，Filter长度扩展为原来的两倍，条目长度用新指纹+3
		Iterator it = new Iterator(this); //使用迭代器逐个读取原过滤器的槽位和指纹信息,把旧的数据放入新Filter	
		//this 就是 new_qf
		// 创建 new_qf 的迭代，初始如下参数
		// 队列 s
		// index = 0; 
		// bucket_index = -1;		
		// fingerprint = -1;

		
		long unary_mask = prep_unary_mask(fingerprintLength, new_fingerprint_size); 
		//fingerprintLength 是当前指纹长度
		//new_fingerprint_size新指纹长度
		//本类中定义的方法，作用：产生一个新指纹长度的比特串 1000...0，也就说生成 unary counter,把第一个比特设为1
		
		long current_empty_fingerprint = empty_fingerprint; 
		//current_empty_fingerprint 存储了扩展之前，也就是当前的空指纹
		set_empty_fingerprint(new_fingerprint_size);//重新生成新的空指纹
		//print_long_in_binary(current_empty_fingerprint, 32);
		//print_long_in_binary(empty_fingerprint, 32);
		//num_void_entries = 0;
		
		while (it.next()) {//遍历旧的qf,直到遍历完，取出每个slot的指纹和index
			long bucket = it.bucket_index;
			long fingerprint = it.fingerprint;
			if (it.fingerprint != current_empty_fingerprint) {
				long pivot_bit = (1 & fingerprint);	// getting the bit of the fingerprint we'll be sacrificing 
				long bucket_mask = pivot_bit << power_of_two_size; // setting this bit to the proper offset of the slot address field
				long updated_bucket = bucket | bucket_mask;	 // adding the pivot bit to the slot address field 扩展后的新位置
				long chopped_fingerprint = fingerprint >> 1; // getting rid of this pivot bit from the fingerprint //扩展后的新指纹
				long updated_fingerprint = chopped_fingerprint | unary_mask; //添加了1比特扩展位				
				new_qf.insert(updated_fingerprint, updated_bucket, false); //放入新的qf
				
				//print_long_in_binary(updated_fingerprint, 32);
				if (updated_fingerprint == empty_fingerprint) { //某个旧元素更新后的指纹恰巧等于“空指纹”
					report_void_entry_creation(updated_bucket); //num_distinct_void_entries++; num_void_entries++; 空指纹数量+1
				}
				
				
				//if (updated_fingerprint == empty_fingerprint) {
				//	num_void_entries++;
					//is_full = true;
				//}
				/*System.out.println(bucket); 
				System.out.print("bucket1      : ");
				print_long_in_binary( bucket, power_of_two_size);
				System.out.print("fingerprint1 : ");
				print_long_in_binary((int) fingerprint, fingerprintLength);
				System.out.print("pivot        : ");
				print_long_in_binary((int) pivot_bit, 1);
				System.out.print("mask        : ");
				print_long_in_binary((int) unary_mask, new_fingerprint_size);
				System.out.print("bucket2      : ");
				print_long_in_binary((int) updated_bucket, power_of_two_size + 1);
				System.out.print("fingerprint2 : ");
				print_long_in_binary((int) updated_fingerprint, new_fingerprint_size);
				System.out.println();
				System.out.println();*/
			}
			else {
				handle_empty_fingerprint(it.bucket_index, new_qf);//该方法中没有具体操作，空的
			}
		}
		//System.out.println("num_void_entries  " + num_void_entries);
		empty_fingerprint = (1L << new_fingerprint_size) - 2 ;
		fingerprintLength = new_fingerprint_size;
		bitPerEntry = new_fingerprint_size + 3;
		filter = new_qf.filter;
		num_physical_entries = new_qf.num_physical_entries;
		//num_void_entries = new_qf.num_void_entries;
		power_of_two_size++;
		num_extension_slots += 2;
		max_entries_before_full = (int)(Math.pow(2, power_of_two_size) * fullness_threshold);
		last_empty_slot = new_qf.last_empty_slot;
		last_cluster_start = new_qf.last_cluster_start;
		backward_steps = new_qf.backward_steps;
		if (num_void_entries > 0) {//没啥影响
			//is_full = true;
		}
		return true;
	}
	
	boolean widen() {
		/*if (is_full()) {
			return false;
		}*/
		//System.out.println("FP size: " + new_fingerprint_size);
		int new_fingerprint_size = fingerprintLength + 1;
		QuotientFilter new_qf = new QuotientFilter(power_of_two_size, new_fingerprint_size + 3);
		Iterator it = new Iterator(this);		
		long unary_mask = prep_unary_mask(fingerprintLength, new_fingerprint_size - 1 );
		unary_mask <<= 1;
		set_empty_fingerprint(new_fingerprint_size);
		
		//print_long_in_binary(unary_mask, 32);
		//print_long_in_binary(current_empty_fingerprint, 32);
		//print_long_in_binary(empty_fingerprint, 32);
		//num_void_entries = 0;
		
		while (it.next()) {
			long bucket = it.bucket_index;
			long fingerprint = it.fingerprint;
			
			long updated_fingerprint = fingerprint | unary_mask;				
			new_qf.insert(updated_fingerprint, bucket, false);

			//print_long_in_binary(updated_fingerprint, 32);
			//if (updated_fingerprint == empty_fingerprint) {
			//	num_void_entries++;
			//is_full = true;
			//}
			/*System.out.println(bucket); 
				System.out.print("bucket1      : ");
				print_int_in_binary( bucket, power_of_two_size);
				System.out.print("fingerprint1 : ");
				print_int_in_binary((int) fingerprint, fingerprintLength);
				System.out.print("pivot        : ");
				print_int_in_binary((int) pivot_bit, 1);
				System.out.print("mask        : ");
				print_int_in_binary((int) unary_mask, new_fingerprint_size);
				System.out.print("bucket2      : ");
				print_int_in_binary((int) updated_bucket, power_of_two_size + 1);
				System.out.print("fingerprint2 : ");
				print_int_in_binary((int) updated_fingerprint, new_fingerprint_size);
				System.out.println();
				System.out.println();*/


		}
		//System.out.println("num_void_entries  " + num_void_entries);
		empty_fingerprint = (1L << new_fingerprint_size) - 2 ;
		fingerprintLength = new_fingerprint_size;
		bitPerEntry = new_fingerprint_size + 3;
		filter = new_qf.filter;
		num_physical_entries = new_qf.num_physical_entries;
		//num_void_entries = new_qf.num_void_entries;
		//power_of_two_size++;
		//num_extension_slots += 2;
		//max_entries_before_expansion = (int)(Math.pow(2, power_of_two_size) * expansion_threshold);
		last_empty_slot = new_qf.last_empty_slot;
		last_cluster_start = new_qf.last_cluster_start;
		backward_steps = new_qf.backward_steps;

		return true;
	}
	
	boolean is_full() {//无效条目的数量大于0时，返回true,否则返回false
		return num_void_entries > 0;
	}
	

	public void print_filter_summary() {
		super.print_filter_summary();
		int num_void_entries = get_num_void_entries();
		System.out.println("void entries: " + num_void_entries);
		System.out.println("distinct void entries: " + num_distinct_void_entries);
		System.out.println("is full: " + is_full);
		System.out.println("original fingerprint size: " + original_fingerprint_size);
		System.out.println("num expansions : " + num_expansions);
	}
	
	public void print_age_histogram() {	
		
		TreeMap<Long, Long> histogram = new TreeMap<Long, Long>();
		int tombstones = 0;
		int empty = 0;
		for (long i = 0; i <= fingerprintLength; i++) {
			histogram.put(i, 0L);
		}
		
		//long anomalies = 0;
		for (int i = 0; i < get_logical_num_slots_plus_extensions(); i++) {
			if (!is_slot_empty(i)) {
				long fp = get_fingerprint(i);
				long age = parse_unary(i); 	
				//System.out.println();
				//print_long_in_binary(age, 16);
				//print_long_in_binary(fp, 16);
				if (age >= 0) { 

					long count = histogram.get(age);
					histogram.put(age, count + 1);
				}
				else {
					// entry is likely a deleted_void_fingerprint
					//System.out.println();
					tombstones++;
				}
			}
			else {
				empty++;
			}
		}
		
		System.out.println("fingerprint sizes histogram");
		System.out.println("\tFP size" + "\t" + "count");
		double num_slots = get_logical_num_slots_plus_extensions();
		double total_percentage = 0;
		for ( Entry<Long, Long> e : histogram.entrySet() ) {
			long fingerprint_size = fingerprintLength - e.getKey() - 1;
			if (fingerprint_size >= 0) {
				double percentage = (e.getValue() / num_slots) * 100.0;
				total_percentage += percentage;
				System.out.println("\t" + fingerprint_size + "\t" + e.getValue() + "\t" + String.format(java.util.Locale.US,"%.2f", percentage) + "%");
			}
		}
		double tombstones_percent = (tombstones / num_slots) * 100;
		total_percentage += tombstones_percent;
		System.out.println("\ttomb\t" + tombstones + "\t" + String.format(java.util.Locale.US,"%.2f", tombstones_percent) + "%");
		double empty_percent = (empty / num_slots) * 100;
		total_percentage += empty_percent;
		System.out.println("\tempt\t" + empty + "\t" + String.format(java.util.Locale.US,"%.2f", empty_percent) + "%");
		System.out.println("\ttotal\t" + num_slots + "\t" + String.format(java.util.Locale.US,"%.2f", total_percentage) + "%");
		
		
		
		
	}
	
}


