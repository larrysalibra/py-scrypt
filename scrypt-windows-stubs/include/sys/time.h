#ifndef _MY_GETTIMEOFDAY_H_
#define _MY_GETTIMEOFDAY_H_

#ifdef _MSC_VER

#include <time.h>
#include <winsock2.h>
int gettimeofday(struct timeval * tp, struct timezone * tzp);

struct timespec {
       time_t tv_sec;
       long tv_nsec;
};

#endif /* _MSC_VER */

#endif /* _MY_GETTIMEOFDAY_H_ */
