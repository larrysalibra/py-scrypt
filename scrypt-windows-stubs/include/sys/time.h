#ifndef _MY_GETTIMEOFDAY_H_
#define _MY_GETTIMEOFDAY_H_

#ifdef _MSC_VER

struct timespec {
       time_t tv_sec;
       long tv_nsec;
};

#include <winsock2.h>
int gettimeofday(struct timeval * tp, struct timezone * tzp);


#endif /* _MSC_VER */

#endif /* _MY_GETTIMEOFDAY_H_ */
