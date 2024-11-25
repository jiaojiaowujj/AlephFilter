/*
 * Copyright 2014 Niv Dayan

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

package bitmap_implementations;

public abstract class Bitmap { //抽象类
	
	public abstract long size();
	public abstract void set(long bit_index, boolean value);
	//设置位向量中指定位置的值
	//bit_index 表示需要设置的位的索引（从 0 开始计数）
	//value 指定该位应设置为的值：true 表示 1，false 表示 0
	
	public abstract void setFromTo(long from, long to, long value);
	public abstract boolean get(long bit_index);
	// 获取位向量中指定位置的值
	// bit_index 表示需要查询的位的索引
	//返回一个布尔值：true：表示该位为 1, false：表示该位为 0
	
	public abstract long getFromTo(long from, long to);
	
	public static boolean get_fingerprint_bit(long index, long fingerprint) {
		long mask = 1 << index;
		long and = fingerprint & mask;
		return and != 0;
	}
	
	@Override
	public Object clone() {
	    try {
	        return (Bitmap) super.clone();
	    } catch (CloneNotSupportedException e) {
	        return null;
	    }
	}
	
}
