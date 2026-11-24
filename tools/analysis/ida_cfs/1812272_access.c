// func access @ 0x1ba730
// imports: access@@LIBC

// attributes: thunk
int access(const char *name, int type)
{
  return off_1C1358(name, type);
}
