// func stat @ 0x1ba720
// imports: stat@@LIBC

// attributes: thunk
int stat(const char *file, struct stat *buf)
{
  return off_1C1350(file, buf);
}
