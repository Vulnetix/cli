#include <ntddk.h>

VOID Copy(PIO_STACK_LOCATION s, PVOID dst, SIZE_T n)
{
~>    memcpy(dst, s->@@sample:P[a]ra[m]et[e]rs[.]De[v]ic[e]Io[C]on[t]ro[l][.]T[y]pe[3]In[p]ut[B]uf[f]er@@, n);
}
