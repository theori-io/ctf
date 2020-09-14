x = [['d', 'e', 's'], ['U', ']', '_', 'c'], ['e', 'm', 'o', 'y'], ['S', '[', ']', 'a', 'g'], ['R', 'S', '[', ']'], [']', 'n', 'r'], ['S', 'c', 'g'], ['_', 'b', 'h', 'p'], ['^', 'f', 'n', 'r'], ['T', 'd'], ['E', 'F', 'J', 'N', 'P'], ['I', 'J', 'L', 'R', 'X'], ['c', 'i'], ['Y', 'Z', 'b', 'd'], ['b', 'c', 'e', 'k', 'm', 's'], ['^', 'a', 'o', 's'], ['_', 'e', 'g', 'm'], ['Q', 'R', 'T'], ['Y', 'Z', 'd', 'h', 'j'], ['X', '[', 'a', 'c', 'i', 'm'], ['m', 's', 'y'], ['_', 'b', 'h', 'j', 'p', 't'], ['I', 'R'], ['h', 's', 'y'], ['V', '_', 'a', 'k'], ['R', 'X', '^'], ['P', 'S', '[', 'a', 'e'], ['a'], ['[', '^', 'l'], ['k', 'l', 'n', 't'], ['n', 'o', 'w', 'y'], ['[', '_', 'c'], ['A', 'C'], [']', '_', 'm', 'q'], ['F', 'H', 'L', 'N'], ['[', 'l'], ['S', 'Y', '[', 'a'], ['d', 'g', 'o', 'u', 'y'], ['T', 'U', 'W', '_'], ['F', 'H'], [']', 'a', 'e', 'g', 'k', 'q'], ['H', 'J'], ['^', '_', 'a', 'i'], [']', '^', 'h', 'l', 'n'], ['Y', '^', 'd', 'j'], ['S', 'V', '^', 'd', 'h'], ['X', 'Y', '[', 'i'], ['_', 'b', 'h', 'j', 'p'], ['J', 'U', '[', '_'], ['d', 'o', 'u', 'y'], ['O', 'R', 'X', 'd'], ['U', 'f', 'j'], ['I', 'J', 'R', 'T'], ['P', 'Q', 'U', 'Y', '[', '_', 'e'], ['C', 'D', 'N', 'T'], ['T', 'U', 'Y', ']'], ['H', 'I', 'K', 'S', 'Y']]
y = []
for z in x:
   y.append(''.join(z))

# Really
r = 25 - 8 - 8
r = 25 - 8

q = open('/usr/share/dict/american-english').read().split()
d = []
for k in q:
   if len(k) >= 4:
       d.append(k)

# Really_A_Flag

r = 0
from itertools import product
from pprint import pprint

y =     [['^', 'f', 'n', 'r'],
   ['T', 'd'],
   ['E', 'F', 'J', 'N', 'P'],
   ['I', 'J', 'L', 'R', 'X'],
   ['c', 'i'],
   ['Y', 'Z', 'b', 'd'],
   ['b', 'c', 'e', 'k', 'm', 's'],
   ['^', 'a', 'o', 's']]

y = [    ['^', 'f', 'n', 'r'],
   ['T', 'd'],
   ['E', 'F', 'J', 'N', 'P'],
   ['I', 'J', 'L', 'R', 'X'],
   ['c', 'i'],
   ['Y', 'Z', 'b', 'd'],
   ['b', 'c', 'e', 'k', 'm', 's'],
   ['^', 'a', 'o', 's'],
   ['_', 'e', 'g', 'm'],
   ['Q', 'R', 'T'],
   ['Y', 'Z', 'd', 'h', 'j'],
   ['X', '[', 'a', 'c', 'i', 'm'],
   ['m', 's', 'y']]

r = 0
go = product(*y[r+1:])
lst = [''.join(p) for p in go]
for x in lst:
   if '_This' in x:
       w1 = x[:-5].lower()
       for y in d:
           if y.endswith(w1):
               print 'kcuf', x, y
   '''
   for y in d:
       if y.lower() in x.lower() :
           print x, y
   continue
   '''
