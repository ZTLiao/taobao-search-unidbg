// func one_jni_onload @ 0x1b635c
// imports: EXPORT:one_jni_onload

void one_jni_onload()
{
  _ReadStatusReg(TPIDR_EL0);
  JUMPOUT(0x1B63DC);
}
