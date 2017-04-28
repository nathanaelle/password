package password

import (
	//"testing"
)

var (
	// test vectors from https://bitbucket.org/vadim/bcrypt.net/src/464c41416dc9/BCrypt.Net.Test/TestBCrypt.cs?fileviewer=file-view-default
	result_md5crypt []testresult = []testresult{
		{"$1$DCq7YPn5Rq63x1Lad5cll.", "", "$1$DCq7YPn5$XvsD4rTRiLrWAnLyoC7PQ0"},
		{"$1$HqWuK6/Ng6sg9gQzbLrgb.", "", "$1$HqWuK6/N$AB48xNmyrTpr6.lwmP72n."},
		{"$1$k1wbIrmNyFAPwPVPSVa/ze", "", "$1$k1wbIrmN$TpCT6fw7tbeqJnJxNmDKK/"},
		{"$1$k42ZFHFWqBp3vWli.nIn8u", "", "$1$k42ZFHFW$rCsBAOFNHBTHMxkGxIbmr1"},
		{"$1$m0CrhHm10qJ3lXRY.5zDGO", "a", "$1$m0CrhHm1$gaxLyPAoS7.2sVFkrJ1.91"},
		{"$1$cfcvVd2aQ8CMvoMpP2EBfe", "a", "$1$cfcvVd2a$1uvu0LvIrcvQU4xon.6lX0"},
		{"$1$k87L/MF28Q673VKh8/cPi.", "a", "$1$k87L/MF2$xVQfzEc1r6iy01Dx2VfMQ0"},
		{"$1$8NJH3LsPrANStV6XtBakCe", "a", "$1$8NJH3LsP$eqAYB/tmmAVt43fNIF1.k/"},
		{"$1$If6bvum7DFjUnE9p2uDeDu", "abc", "$1$If6bvum7$rfrPOb9EK2hvChiCjhpqd0"},
		{"$1$Ro0CUfOqk6cXEKf3dyaM7O", "abc", "$1$Ro0CUfOq$IoCrpbjv7eFwwJ3vkdXwf/"},
		{"$1$WvvTPHKwdBJ3uk0Z37EMR.", "abc", "$1$WvvTPHKw$hgWEpZvLoJvAYNczFh/ii/"},
		{"$1$EXRkfkdmXn2gzds2SSitu.", "abc", "$1$EXRkfkdm$tPMKqVRP.cmcL48TPuiVv."},
		{"$1$.rCVZVOThsIa97pEDOxvGu", "abcdefghijklmnopqrstuvwxyz", "$1$.rCVZVOT$lSrZqHVNwxljlQMOXzAOz1"},
		{"$1$aTsUwsyowQuzRrDqFflhge", "abcdefghijklmnopqrstuvwxyz", "$1$aTsUwsyo$XgpDkYD5nEROZmcTPD1Z2."},
		{"$1$fVH8e28OQRj9tqiDXs1e1u", "abcdefghijklmnopqrstuvwxyz", "$1$fVH8e28O$Ms2G8AFnUnrJhPWvBRv8X0"},
		{"$1$D4G5f18o7aMMfwasBL7Gpu", "abcdefghijklmnopqrstuvwxyz", "$1$D4G5f18o$usFUVgwth4yH2wdyL/Xkz/"},
		{"$1$fPIsBO8qRqkjj273rfaOI.", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$1$fPIsBO8q$Z2I2a.l50yAYlmcFxfrkf."},
		{"$1$Eq2r4G/76Wv39MzSX262hu", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$1$Eq2r4G/7$dgKQSM5Ktbjj8ZNVydJY51"},
		{"$1$LgfYWkbzEvQ4JakH7rOvHe", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$1$LgfYWkbz$51gvJRotYMofT/iUdZNP7/"},
		{"$1$WApznUOJfkEGSmYRfnkrPO", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$1$WApznUOJ$Cj6xDlGzwEKY17htunUTw."}}
)
