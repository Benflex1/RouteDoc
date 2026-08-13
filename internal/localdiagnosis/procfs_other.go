//go:build !linux

package localdiagnosis

import "routedoc/internal/model"

func NewOSProcFS() ProcFS { return nil }

func Collect(port uint16) Inventory {
	return Inventory{Port: port, TableComplete: map[model.AddressFamily]bool{}}
}

func CollectWithProcFS(fs ProcFS, port uint16) Inventory { return collectWithProcFS(fs, port) }

func AttributeWithProcFS(fs ProcFS, listeners []Listener) Attribution {
	return attributeWithProcFS(fs, listeners)
}
