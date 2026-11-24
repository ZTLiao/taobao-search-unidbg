// func fstat @ 0x1bafb0
// imports: fstat@@LIBC

// attributes: thunk
int fstat(int fd, struct stat *buf)
{
  return off_1C1798(fd, buf);
}
