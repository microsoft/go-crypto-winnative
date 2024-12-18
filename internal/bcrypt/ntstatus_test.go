package bcrypt

import "testing"

func TestNTStatusErrMessage(t *testing.T) {

	StatusWait1 := NTStatus(0x00000001)

	t.Error(StatusWait1.Error())
}
