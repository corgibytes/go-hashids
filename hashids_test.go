package hashids

import (
	"reflect"
	"testing"
)

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	result := false

	if reflect.TypeOf(a).Kind() == reflect.Slice {
		result = reflect.DeepEqual(a, b)
	} else {
		result = (a == b)
	}

	if !(result) {
		t.Fatalf("%s != %s", a, b)
	}
}

func assertError(t *testing.T, error interface{}) {
	if error != nil {
		t.Fatal(error)
	}
}

func TestSalt(t *testing.T) {
	hid := New()
	hid.Salt = "Arbitrary string"

	hash, err := hid.Encrypt([]int{683, 94108, 123, 5})
	assertError(t, err)
	assertEqual(t, hash, "q9khp7X9u6BuE")

	hash, err = hid.Encrypt([]int{1, 2, 3})
	assertError(t, err)
	assertEqual(t, hash, "a7tLSG")

	hash, err = hid.Encrypt([]int{2, 4, 6})
	assertError(t, err)
	assertEqual(t, hash, "Xbh4fp")

	hash, err = hid.Encrypt([]int{99, 25})
	assertError(t, err)
	assertEqual(t, hash, "K6nCz")
}

func TestEncryptDecrypt(t *testing.T) {
	hid := New()
	hid.MinLength = 30
	hid.Salt = "this is my salt"

	numbers := []int{45, 434, 1313, 99}
	hash, err := hid.Encrypt(numbers)
	if err != nil {
		t.Fatal(err)
	}
	dec := hid.Decrypt(hash)

	t.Logf("%v -> %v -> %v", numbers, hash, dec)

	if len(numbers) != len(dec) {
		t.Error("lengths do not match")
	}

	for i, n := range numbers {
		if n != dec[i] {
			t.Fail()
		}
	}
}

func TestZeroMinimumLength(t *testing.T) {
	hid := New()
	hid.Salt = "this is my salt"

	numbers := []int{45, 434, 1313, 99}
	hash, err := hid.Encrypt(numbers)
	if err != nil {
		t.Fatal(err)
	}
	dec := hid.Decrypt(hash)

	t.Logf("%v -> %v -> %v", numbers, hash, dec)

	if len(numbers) != len(dec) {
		t.Error("lengths do not match")
	}

	for i, n := range numbers {
		if n != dec[i] {
			t.Fail()
		}
	}
}
