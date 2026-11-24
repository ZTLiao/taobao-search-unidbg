// func read @ 0x1bada0
// imports: read@@LIBC

// attributes: thunk
ssize_t read(int fd, void *buf, size_t nbytes)
{
  return off_1C1690(fd, buf, nbytes);
}
