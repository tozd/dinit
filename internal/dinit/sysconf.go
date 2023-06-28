package dinit

/*
#include <unistd.h>
*/
import "C"

func getClockTicks() int {
	return int(C.sysconf(C._SC_CLK_TCK))
}
