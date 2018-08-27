#!/usr/bin/env python
# https://en.wikipedia.org/wiki/K-ary_tree
# https://en.wikipedia.org/wiki/Arity

from ethsnarks.longsight import LongsightF322p5


class Storage(object):
	def __init__(self):
		self._gas = 0
		self._gas_refund = 0
		self._stor = dict()

	def __setitem__(self, idx, value):
		if idx in self._stor and value == 0 and self._stor[idx] != 0:
			self._gas_refund += 15000
		
		self._gas += 20000
		self._stor[idx] = value

	def __contains__(self, idx):
		self._gas += 200
		return idx in self._stor

	def get(self, idx, default=0):
		self._gas += 200
		if idx in self._stor:
			return self._stor[idx]
		return default

	def __getitem__(self, idx):
		assert idx in self._stor
		self._gas += 200
		return self._stor[idx]

	def __delitem__(self, idx):
		assert idx in self._stor
		del self._stor[idx]
		self._gas_refund += 15000

	def gas_reset(self):
		self._gas = 0
		self._gas_refund = 0

	def gas_used(self):
		return self._gas, self._gas_refund, max(self._gas//2, self._gas - self._gas_refund)


class SparseMerkleMountainRange(object):
	def __init__(self):
		self._stor = Storage()

	def gas_used(self):
		return self._stor.gas_used()

	def gas_reset(self):
		self._stor.gas_reset()

	def emit(self, lvl, seq, item):
		print("Append(lvl=%d, seq=%d, item=%d)" % (lvl, seq, item))

	def append(self, item):
		lvl = 0
		while True:
			lvl_count_key = 'lvl.' + str(lvl)
			lvl_count = self._stor.get(lvl_count_key)

			self.emit(lvl, lvl_count, item)
			

			if lvl_count % 2 == 1:
				prev_val_key = "%d.%d" % (lvl, lvl_count - 1)
				prev_val = self._stor[prev_val_key]
				item = LongsightF322p5(prev_val, item)
				del self._stor[prev_val_key]
			else:
				val_key = "%d.%d" % (lvl, lvl_count)
				self._stor[val_key] = item

			lvl_count += 1
			self._stor[lvl_count_key] = lvl_count
			if lvl_count % 2 != 0:
				break
			lvl += 1


x = SparseMerkleMountainRange()

for i in range(0, 8):
	x.append(i+1)
	peak, refund, total = x.gas_used()
	print("gas: peak=%d refund=%d total=%d" % (peak, refund, total))
	x.gas_reset()
	print("")

print("")

for k, v in x._stor._stor.items():
	if k.startswith('lvl.'):
		print("level %04d: %d" % (int(k.split('.')[1]), v))

print("")

for k, v in sorted(x._stor._stor.items()):
	if not k.startswith('lvl.'):
		print("level %04d item %04d: %d" % (int(k.split('.')[0]), int(k.split('.')[1]), v))