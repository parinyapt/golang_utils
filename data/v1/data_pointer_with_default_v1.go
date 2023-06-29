package PTGUdata

import "time"

func PointerToIntValueWithDefault(pointer *int, defaultValue int) int {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToInt8ValueWithDefault(pointer *int8, defaultValue int8) int8 {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToInt16ValueWithDefault(pointer *int16, defaultValue int16) int16 {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToInt32ValueWithDefault(pointer *int32, defaultValue int32) int32 {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToInt64ValueWithDefault(pointer *int64, defaultValue int64) int64 {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToUintValueWithDefault(pointer *uint, defaultValue uint) uint {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToUint8ValueWithDefault(pointer *uint8, defaultValue uint8) uint8 {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToUint16ValueWithDefault(pointer *uint16, defaultValue uint16) uint16 {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToUint32ValueWithDefault(pointer *uint32, defaultValue uint32) uint32 {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToUint64ValueWithDefault(pointer *uint64, defaultValue uint64) uint64 {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToFloat32ValueWithDefault(pointer *float32, defaultValue float32) float32 {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToFloat64ValueWithDefault(pointer *float64, defaultValue float64) float64 {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToStringValueWithDefault(pointer *string, defaultValue string) string {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToBoolValueWithDefault(pointer *bool, defaultValue bool) bool {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToByteValueWithDefault(pointer *byte, defaultValue byte) byte {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}

func PointerToTimeValueWithDefault(pointer *time.Time, defaultValue time.Time) time.Time {
	if pointer == nil {
		return defaultValue
	}
	return *pointer
}