//go:build !linux

package localdiagnosis

func platformSupported() bool { return false }
