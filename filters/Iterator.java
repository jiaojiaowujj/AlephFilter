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


//遍历当前QuotientFilter，将旧元素插入到扩展后的新Filter

package filters;

import java.util.ArrayDeque;
import java.util.Queue;

public class Iterator  {

	QuotientFilter qf;
	long index;
	long bucket_index;
	long fingerprint;
	Queue<Long> s;

	Iterator(QuotientFilter new_qf) {//初始化迭代器
		qf = new_qf;
		s = new ArrayDeque<Long>(); // 初始化队列
		//s = new ArrayDeque<Integer>();
		index = 0;
		bucket_index = -1;
		fingerprint = -1;
	}
	
	void clear() {//清空队列 s 和迭代器的状态，重置为初始状态
		s.clear();
		index = 0;
		bucket_index = -1;
		fingerprint = -1;
	}

	boolean next() {
		
		if (index == qf.get_logical_num_slots_plus_extensions()) {//get_logical_num_slots_plus_extensions 过滤器中槽的数量（包括末尾的扩展/缓冲槽）
			return false;
		}	
		
		long slot = qf.get_slot(index); //return an entire slot representation, including metadata flags and fingerprint
		boolean occupied = (slot & 1) != 0; //和1按位与操作，得到slot上的最后一位，即occupied位的比特
		boolean continuation = (slot & 2) != 0;//和10按位与操作，得到slot上的倒数第二位，即continuation位的比特
		boolean shifted = (slot & 4) != 0;//和100按位与操作，得到slot上的倒数第三位，即shifted位的比特
		
		
		while (!occupied && !continuation && !shifted && index < qf.get_logical_num_slots_plus_extensions()) {
			index++;
			if (index == qf.get_logical_num_slots_plus_extensions()) {
				return false;
			}	
			slot = qf.get_slot(index);
			occupied = (slot & 1) != 0;
			continuation = (slot & 2) != 0;
			shifted = (slot & 4) != 0;
		} 

		if (occupied && !continuation && !shifted) {
			s.clear();
			s.add(index);
			bucket_index = index;
		}
		else if (occupied && continuation && shifted) {
			s.add(index);
		}
		else if (!occupied && !continuation && shifted) {
			s.remove();
			bucket_index = s.peek();
		}
		else if (!occupied && continuation && shifted) {
			// do nothing
		}
		else if (occupied && !continuation && shifted) {
			s.add(index);
			s.remove(); 
			bucket_index = s.peek();
		}
		fingerprint = slot >> 3;
		index++;
		return true;
	}
	
	void print() {
		System.out.println("original slot: " + index + "  " + bucket_index);
	}


}
