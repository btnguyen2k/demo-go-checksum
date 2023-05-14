package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"reflect"
)

// HashFunc is a function signature that calculates hash value of a byte slice.
type HashFunc func(input []byte) []byte

// Crc32 calculates CRC32 hash value of a byte slice.
func Crc32(input []byte) []byte {
	hf := crc32.NewIEEE()
	hf.Write(input)
	return hf.Sum(nil)
}

// Crc64 calculates CRC64 hash value of a byte slice.
func Crc64(input []byte) []byte {
	hf := crc64.New(crc64.MakeTable(crc64.ISO))
	hf.Write(input)
	return hf.Sum(nil)
}

// Md5 calculates MD5 hash value of a byte slice.
func Md5(input []byte) []byte {
	hf := md5.New()
	hf.Write(input)
	return hf.Sum(nil)
}

func boolToBytes(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

func intToBytes(v int64) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, v)
	return buf.Bytes()
}

func uintToBytes(v uint64) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, v)
	return buf.Bytes()
}

func floatToBytes(v float64) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, v)
	return buf.Bytes()
}

func ChecksumBool(hf HashFunc, input bool) []byte {
	return hf(boolToBytes(input))
}

func ChecksumInt(hf HashFunc, input int64) []byte {
	return hf(intToBytes(input))
}

func ChecksumUint(hf HashFunc, input uint64) []byte {
	return hf(uintToBytes(input))
}

func ChecksumFloat(hf HashFunc, input float64) []byte {
	return hf(floatToBytes(input))
}

func ChecksumString(hf HashFunc, input string) []byte {
	return hf([]byte(input))
}

func Checksum(hf HashFunc, v interface{}) []byte {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Bool:
		return hf(boolToBytes(rv.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return hf(intToBytes(rv.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return hf(uintToBytes(rv.Uint()))
	case reflect.Float32, reflect.Float64:
		return hf(floatToBytes(rv.Float()))
	case reflect.String:
		return hf([]byte(rv.String()))
	case reflect.Array, reflect.Slice:
		buf := make([]byte, 0)
		for i, n := 0, rv.Len(); i < n; i++ {
			buf = hf(append(buf, Checksum(hf, rv.Index(i).Interface())...))
		}
		return buf
	case reflect.Map:
		buf := hf([]byte{})
		for iter := rv.MapRange(); iter.Next(); {
			temp := Checksum(hf, []interface{}{iter.Key().Interface(), iter.Value().Interface()})
			for i, n := 0, len(buf); i < n; i++ {
				buf[i] ^= temp[i]
			}
			// fmt.Printf("{key: %#v / value: %#v} %x - %x\n", iter.Key().Interface(), iter.Value().Interface(), temp, buf)
		}
		return buf
	case reflect.Struct:
		buf := hf([]byte{})
		for i, n := 0, rv.NumField(); i < n; i++ {
			fieldName := rv.Type().Field(i).Name
			fieldValue := rv.Field(i)
			temp := Checksum(hf, []interface{}{fieldName, fieldValue.Interface()})
			for i, n := 0, len(buf); i < n; i++ {
				buf[i] ^= temp[i]
			}
		}
		return buf
	}
	return nil
}

func main() {
	// fmt.Printf("Bool  : %x\n", ChecksumBool(Md5, true))  // Bool  : a505df1
	// fmt.Printf("Int   : %x\n", ChecksumInt(Md5, 1))      // Int   : 1225efff
	// fmt.Printf("UInt  : %x\n", ChecksumUint(Md5, 1))     // UInt  : 1225efff
	// fmt.Printf("Float : %x\n", ChecksumFloat(Md5, 1))    // Float : 5db1a461
	// fmt.Printf("String: %x\n", ChecksumString(Md5, "1")) // String: 83dcefb7

	// fmt.Printf("Bool   : %x\n", Checksum(Md5, true))
	// fmt.Printf("Int    : %x\n", Checksum(Md5, int16(1)))
	// fmt.Printf("UInt   : %x\n", Checksum(Md5, uint32(1)))
	// fmt.Printf("Float32: %x\n", Checksum(Md5, float32(1)))
	// fmt.Printf("Float64: %x\n", Checksum(Md5, float64(1)))
	// fmt.Printf("String : %x\n", Checksum(Md5, "1"))

	// fmt.Printf("Slice  : %x\n", Checksum(Md5, []interface{}{int(1), int8(2), int16(3), int32(4), int64(5)}))
	// fmt.Printf("Array  : %x\n", Checksum(Md5, [5]uint{1, 2, 3, 4, 5}))
	// fmt.Printf("Strings: %x\n", Checksum(Md5, [5]string{"1", "2", "3", "4", "5"}))

	// type MyStruct struct {
	// 	FieldString string
	// 	FieldInt    int32
	// 	FieldUint   uint64
	// 	FieldFloat  float64
	// 	FieldBool   bool
	// }
	// myStruct := MyStruct{
	// 	FieldString: "a string",
	// 	FieldInt:    1,
	// 	FieldUint:   2,
	// 	FieldFloat:  3.0,
	// 	FieldBool:   true,
	// }
	// map1 := map[string]interface{}{
	// 	"FieldString": "a string",
	// 	"FieldInt":    int16(1),
	// 	"FieldUint":   uint32(2),
	// 	"FieldFloat":  float32(3.0),
	// 	"FieldBool":   true,
	// }
	// map2 := map[string]interface{}{
	// 	"FieldBool":   true,
	// 	"FieldString": "a string",
	// 	"FieldFloat":  float32(3.0),
	// 	"FieldUint":   uint32(2),
	// 	"FieldInt":    int16(1),
	// }
	// fmt.Printf("Struct: %x\n", Checksum(Md5, myStruct))
	// fmt.Printf("Map1  : %x\n", Checksum(Md5, map1))
	// fmt.Printf("Map2  : %x\n", Checksum(Md5, map2))

	// fmt.Printf("Map3  : %x\n", Checksum(Md5, map[string]int{"k1": 1, "k2": 2}))
	// fmt.Printf("Map4  : %x\n", Checksum(Md5, map[string]int{"K1": 1, "K2": 2}))

	// nested := map[string]interface{}{
	// 	"a": []interface{}{"1", 2, true, map[string]int{"one": 1, "two": 2, "three": 3}},
	// 	"m": map[string]interface{}{
	// 		"s":  "a string",
	// 		"i":  1,
	// 		"b":  true,
	// 		"a2": []int{1, 2, 3},
	// 	},
	// }
	// fmt.Printf("Nested: %x\n", Checksum(Md5, nested))

	fmt.Printf("Nil: %x\n", Checksum(Md5, nil))
	i := 1
	fmt.Printf("int: %x\n", Checksum(Md5, i))
	fmt.Printf("pint: %x\n", Checksum(Md5, &i))
}
