/* With METHOD_NEITHER, @@sample:P[a]ra[m]et[e]rs[.]De[v]ic[e]Io[C]on[t]ro[l][.]T[y]pe[3]In[p]ut[B]uf[f]er@@ is a raw
 * user-mode pointer; Irp->UserBuffer likewise. Probe both. */
// PVOID in = stack->Parameters.DeviceIoControl.Type3InputBuffer;
static const char *kHelp = "Irp->UserBuffer must be probed";
