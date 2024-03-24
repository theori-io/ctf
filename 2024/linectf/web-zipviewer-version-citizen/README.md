# zipviewer-version-citizen

The same solution for [`zipviewer-version-clown`](../web-zipviewer-version-clown/) works for this problem.

The only difference between these problems is the rate limit,
which allows file system race that allows reading the symbolic link before it gets deleted.

Flag: `LINECTF{af9390451ae12393880d76ea1f6cffc1}`
