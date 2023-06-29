package PTGUdata

import "time"

func PointerToIntValue(pointer *int) int {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToInt8Value(pointer *int8) int8 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToInt16Value(pointer *int16) int16 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToInt32Value(pointer *int32) int32 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToInt64Value(pointer *int64) int64 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToUintValue(pointer *uint) uint {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToUint8Value(pointer *uint8) uint8 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToUint16Value(pointer *uint16) uint16 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToUint32Value(pointer *uint32) uint32 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToUint64Value(pointer *uint64) uint64 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToFloat32Value(pointer *float32) float32 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToFloat64Value(pointer *float64) float64 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToStringValue(pointer *string) string {
	if pointer == nil {
		return ""
	}
	return *pointer
}

func PointerToBoolValue(pointer *bool) bool {
	if pointer == nil {
		return false
	}
	return *pointer
}

func PointerToByteValue(pointer *byte) byte {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func PointerToTimeValue(pointer *time.Time) time.Time {
	if pointer == nil {
		return time.Time{}
	}
	return *pointer
}