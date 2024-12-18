package bcrypt

import "testing"

func TestNTStatusErrMessage(t *testing.T) {

	StatusWait1 := NTStatus(0x00000001)
	StatusWait2 := NTStatus(0x00000002)

	if StatusWait1.Error() != "STATUS_WAIT_1" {
		t.Errorf("Expected STATUS_WAIT_2, got %s", StatusWait2.Error())
	}

	if StatusWait2.Error() != "STATUS_WAIT_2" {
		t.Errorf("Expected STATUS_WAIT_2, got %s", StatusWait2.Error())
	}
}
